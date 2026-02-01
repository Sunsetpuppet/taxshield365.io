import streamlit as st
import requests
import json
import base64
import time
import uuid
from fpdf import FPDF
import stripe

# --- CONFIGURATION ---
st.set_page_config(page_title="TaxShield FINAL v3.5", page_icon="🛡️", layout="centered")

# --- 0. SECURITY CONSTANTS ---
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB Limit

# --- 1. HELPER FUNCTIONS ---
def safe_float(val):
    try:
        return float(val)
    except:
        return 0.0

def check_rate_limit():
    if "last_scan" not in st.session_state:
        st.session_state.last_scan = 0
    
    # 30-second cooldown to save API costs
    if time.time() - st.session_state.last_scan < 30:
        st.error("⏳ Please wait 30 seconds before scanning another paystub.")
        st.stop()
    
    st.session_state.last_scan = time.time()

def get_best_model(api_key):
    url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    try:
        response = requests.get(url)
        if response.status_code != 200:
            return None, f"ListModels Failed: {response.text}"
        data = response.json()
        models = data.get('models', [])
        valid_models = [m['name'] for m in models if 'generateContent' in m.get('supportedGenerationMethods', [])]
        if not valid_models: return None, "No valid models found."
        for m in valid_models:
            if 'gemini-1.5-flash' in m and 'latest' in m: return m, None
        for m in valid_models:
            if 'gemini-1.5-flash' in m: return m, None
        return valid_models[0], None
    except Exception as e:
        return None, str(e)

def analyze_paystub_smart(image_bytes):
    api_key = st.secrets.get("GOOGLE_API_KEY")
    if not api_key: return {"error": "🚨 STOP: API Key missing."}

    model_name, error = get_best_model(api_key)
    if error: return {"error": f"Model Discovery Error: {error}"}
    if model_name.startswith("models/"): model_name = model_name.replace("models/", "")

    base64_image = base64.b64encode(image_bytes).decode('utf-8')
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
    headers = {'Content-Type': 'application/json'}
    
    prompt_text = """
    You are a Forensic Payroll Auditor. Extract YTD totals.
    Return ONLY a raw JSON string:
    {
      "employee_name": "string or null",
      "employer_name": "string or null",
      "pay_period_end": "YYYY-MM-DD",
      "ytd_overtime_income": number or 0.0,
      "ytd_double_time_income": number or 0.0,
      "ytd_tip_income": number or 0.0
    }
    """
    payload = {
        "contents": [{
            "parts": [
                {"text": prompt_text},
                {"inline_data": {"mime_type": "image/jpeg", "data": base64_image}}
            ]
        }]
    }

    try:
        response = requests.post(url, headers=headers, json=payload)
        if response.status_code == 200:
            try:
                result_text = response.json()['candidates'][0]['content']['parts'][0]['text']
                clean_json = result_text.replace("```json", "").replace("```", "").strip()
                return json.loads(clean_json)
            except Exception:
                return {"error": "AI Parsing Error"}
        else:
            return {"error": f"Google Error: {response.text}"}
    except Exception as e:
        return {"error": f"Connection Failed: {str(e)}"}

def create_audit_pdf(data, ot_gross, dt_gross, tips, ot_exempt, dt_exempt, total_exempt, refund):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="Forensic Tax Audit Report (2025)", ln=True, align='C')
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 10, txt="Compliant with 2025 'Premium Only' & Tip Deduction Rules", ln=True, align='C')
    pdf.ln(10)
    
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 8, txt=f"Employee: {data.get('employee_name', 'Unknown')}", ln=True)
    pdf.cell(200, 8, txt=f"Employer: {data.get('employer_name', 'Unknown')}", ln=True)
    pdf.cell(200, 8, txt=f"Date: {data.get('pay_period_end', 'Unknown')}", ln=True)
    pdf.ln(10)
    
    pdf.set_fill_color(220, 220, 220)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(80, 10, txt="Income Type", border=1, fill=True)
    pdf.cell(50, 10, txt="Gross YTD", border=1, fill=True)
    pdf.cell(60, 10, txt="Tax-Exempt Portion", border=1, fill=True, ln=True)
    
    pdf.set_font("Arial", size=12)
    pdf.cell(80, 10, txt="Overtime (1.5x)", border=1)
    pdf.cell(50, 10, txt=f"${ot_gross:,.2f}", border=1)
    pdf.cell(60, 10, txt=f"${ot_exempt:,.2f} (33%)", border=1, ln=True)
    pdf.cell(80, 10, txt="Double Time (2.0x)", border=1)
    pdf.cell(50, 10, txt=f"${dt_gross:,.2f}", border=1)
    pdf.cell(60, 10, txt=f"${dt_exempt:,.2f} (25%)", border=1, ln=True)
    pdf.cell(80, 10, txt="Tips (100% Deductible)", border=1)
    pdf.cell(50, 10, txt=f"${tips:,.2f}", border=1)
    pdf.cell(60, 10, txt=f"${tips:,.2f} (100%)", border=1, ln=True)
    
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(130, 10, txt="TOTAL DEDUCTIBLE INCOME", border=1, align='R')
    pdf.cell(60, 10, txt=f"${total_exempt:,.2f}", border=1, ln=True)
    
    pdf.ln(10)
    pdf.set_text_color(0, 128, 0)
    pdf.cell(200, 10, txt=f"ESTIMATED REFUND INCREASE: ${refund:,.2f}", ln=True)
    return pdf.output(dest='S').encode('latin-1')

# --- 2. PAYMENT LOGIC (With Nonce Security) ---
def create_stripe_session(ot_val, dt_val, tips_val):
    stripe.api_key = st.secrets["STRIPE_API_KEY"]
    
    # SECURITY UPGRADE: Add a unique nonce to the fingerprint
    nonce = str(uuid.uuid4())
    st.session_state['payment_nonce'] = nonce
    fingerprint = f"{float(ot_val):.2f}|{float(dt_val):.2f}|{float(tips_val):.2f}|{nonce}"
    
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            # --- USING YOUR LIVE PRODUCT ID ---
            line_items=[{
                'price': 'price_1SuP4sEHfkgHgdDFmTa78q2f',
                'quantity': 1,
            }],
            mode='payment',
            # ✅ FIXED: Redirect to your live domain
            success_url='https://taxshield365.io/?session_id={CHECKOUT_SESSION_ID}', 
            cancel_url='https://taxshield365.io/',
            metadata={'data_fingerprint': fingerprint} 
        )
        return session.id, session.url
    except Exception as e:
        # ✅ FIXED: Indentation is now correct for the except block
        st.error(f"⚠️ STRIPE ERROR: {e}") 
        return None, None

def check_payment_status(session_id, current_ot, current_dt, current_tips):
    stripe.api_key = st.secrets["STRIPE_API_KEY"]
    try:
        session = stripe.checkout.Session.retrieve(session_id)
        if session.payment_status != 'paid':
            return False, "Not Paid"

        stored_fingerprint = session.metadata.get('data_fingerprint', "")
        
        # Verify against the Nonce stored in session
        nonce = st.session_state.get('payment_nonce', "")
        current_fingerprint = f"{float(current_ot):.2f}|{float(current_dt):.2f}|{float(current_tips):.2f}|{nonce}"
        
        if stored_fingerprint != current_fingerprint:
            return False, "Mismatch"
            
        return True, "Success"
    except:
        return False, "Error"

# --- 3. RESET HANDLER ---
def reset_payment():
    st.session_state['stripe_url'] = None
    st.session_state['stripe_session_id'] = None
    st.session_state['paid'] = False

# --- 4. MAIN UI ---
def main():
    admin_secret = st.secrets.get("ADMIN_PASSWORD", "admin2025") 
    
    # Initialize Session States
    if 'stripe_session_id' not in st.session_state: st.session_state['stripe_session_id'] = None
    if 'stripe_url' not in st.session_state: st.session_state['stripe_url'] = None
    if 'paid' not in st.session_state: st.session_state['paid'] = False
    if 'report_data' not in st.session_state: st.session_state['report_data'] = None
    if 'payment_nonce' not in st.session_state: st.session_state['payment_nonce'] = ""

    try: query_params = st.query_params
    except: query_params = st.experimental_get_query_params()
    
    is_admin_url = "admin" in query_params
    
    if "session_id" in query_params:
        st.session_state['stripe_session_id'] = query_params["session_id"]
    
    bypass_payment = False
    if is_admin_url:
        with st.sidebar:
            st.header("🔧 Developer Mode")
            if st.text_input("Admin Password", type="password") == admin_secret:
                st.success("Admin Active")
                bypass_payment = st.checkbox("Bypass Payment Gateway", value=True)

    st.title("🛡️ TaxShield 365")
    st.markdown("### Did the IRS miss your Overtime Exemption?")
    st.info("New 2025 Laws: No Tax on Tips (up to $25k) & No Tax on Overtime Premium.")
    st.write("---")

    # --- UPLOAD SECTION ---
    is_locked = st.session_state['paid']
    
    with st.container():
        with st.expander("📂 Upload Paystub", expanded=(st.session_state['report_data'] is None)):
            with st.form("scan_form", clear_on_submit=False):
                uploaded_file = st.file_uploader("Upload Final 2025 Paystub", type=['png', 'jpg', 'jpeg'], disabled=is_locked)
                submitted = st.form_submit_button("🚀 Run Forensic Scan", disabled=is_locked)
                
                if submitted:
                    reset_payment() 
                    
                    if not uploaded_file:
                        st.error("⚠️ Please select a file first.")
                    # SECURITY: Size Limit
                    elif uploaded_file.size > MAX_FILE_SIZE:
                        st.error("❌ File is too large (Max 5MB). Please compress it.")
                    else:
                        # SECURITY: Rate Limit
                        check_rate_limit()
                        
                        with st.spinner("Analyzing Paystub Logic..."):
                            bytes_data = uploaded_file.getvalue()
                            result = analyze_paystub_smart(bytes_data)
                            if "error" in result: st.error(result['error'])
                            else:
                                st.session_state['report_data'] = result
                                st.rerun()

    # --- RESULTS SECTION ---
    if st.session_state['report_data']:
        data = st.session_state['report_data']
        st.write("---")
        st.write("### 2. Verify Your Gross Numbers")
        if is_locked:
            st.warning("🔒 **Report Locked.** To change numbers, click 'Start Over'.")
        else:
            st.markdown(":red[**Please confirm these numbers match your paystub exactly.**]")
        
        c1, c2, c3 = st.columns(3)
        
        # Use safe_float for security
        with c1: ot_gross = st.number_input("Overtime YTD (Gross)", value=safe_float(data.get('ytd_overtime_income')), format="%.2f", disabled=is_locked, on_change=reset_payment)
        with c2: dt_gross = st.number_input("Double Time YTD (Gross)", value=safe_float(data.get('ytd_double_time_income')), format="%.2f", disabled=is_locked, on_change=reset_payment)
        with c3: tips = st.number_input("Tips YTD", value=safe_float(data.get('ytd_tip_income')), format="%.2f", disabled=is_locked, on_change=reset_payment)

        ot_exempt = ot_gross / 3.0
        dt_exempt = dt_gross / 4.0
        tips_capped = min(tips, 25000.00)
        total_exempt = ot_exempt + dt_exempt + tips_capped
        est_refund = total_exempt * 0.22 

        st.write("---")
        st.subheader("📊 Final Result")
        m1, m2 = st.columns(2)
        m1.metric("Total Tax-Exempt", f"${total_exempt:,.2f}")
        m2.metric("Est. Refund Increase", f"${est_refund:,.2f}", delta="YOUR MONEY")
        st.write("---")
        
        with st.container():
            if st.session_state['paid']:
                 st.success("✅ **Payment Verified! Report Generated.**")
                 pdf_bytes = create_audit_pdf(data, ot_gross, dt_gross, tips_capped, ot_exempt, dt_exempt, total_exempt, est_refund)
                 st.download_button(label="📄 Download IRS Evidence Packet (PDF)", data=pdf_bytes, file_name="TaxShield_Strict_Audit_2025.pdf", mime="application/pdf")
                 
                 st.write("")
                 if st.button("← Start Over (New Scan)"):
                     st.session_state.clear()
                     st.rerun()
            
            else:
                st.warning("⚠️ **Protect Yourself from Audit.**")
                st.markdown(f"Unlock the **IRS Evidence Packet** to claim your **${est_refund:,.0f}** refund.")
                col_p1, col_p2 = st.columns([1, 2])
                with col_p1:
                    st.markdown("### ~~**$89**~~") 
                    st.caption("CPA Cost")
                with col_p2:
                    if bypass_payment:
                        if st.button("🔓 UNLOCK (ADMIN BYPASS)", type="primary"):
                            st.session_state['paid'] = True
                            st.rerun()
                    else:
                        # 1. CREATE SESSION
                        if st.session_state['stripe_url'] is None:
                             session_id, session_url = create_stripe_session(ot_gross, dt_gross, tips_capped)
                             if session_id:
                                 st.session_state['stripe_session_id'] = session_id
                                 st.session_state['stripe_url'] = session_url
                        
                        # 2. SHOW LINK
                        if st.session_state['stripe_url']:
                            st.markdown(f"### 👉 [CLICK HERE TO PAY $39.99]({st.session_state['stripe_url']})")
                        else:
                            st.error("Unable to connect to Payment Gateway. Please refresh.")
                        
                        st.write("")
                        
                        # 3. VERIFY
                        if st.button("I have completed payment"):
                            with st.spinner("Verifying Transaction..."):
                                sid_to_check = st.session_state.get('stripe_session_id')
                                if not sid_to_check:
                                    st.error("❌ No active payment session found.")
                                else:
                                    is_paid, reason = check_payment_status(sid_to_check, ot_gross, dt_gross, tips_capped)
                                    
                                    if is_paid:
                                        st.success("Payment Confirmed!")
                                        st.session_state['paid'] = True
                                        st.rerun()
                                    elif reason == "Mismatch":
                                        st.error("🚨 **Security Alert:** Data mismatch.")
                                        st.error("Please click 'Unlock' again to generate a secure link.")
                                        reset_payment()
                                    else:
                                        st.error("❌ Payment not found. Please complete checkout first.")

if __name__ == "__main__":
    main()
