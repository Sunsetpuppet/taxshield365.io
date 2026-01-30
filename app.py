import streamlit as st
import requests
import json
import base64
import time
import uuid
from fpdf import FPDF
import stripe

st.set_page_config(page_title="TaxShield FINAL v3.1", page_icon="🛡️", layout="centered")

# =========================
# 🔒 MAINTENANCE LOCK
# =========================
def maintenance_lock():
    PASSWORD = st.secrets["MAINTENANCE_PASSWORD"]
    st.title("🔒 Site Under Maintenance")
    st.write("This app is temporarily offline for upgrades.")
    pwd = st.text_input("Enter access password", type="password")
    if pwd != PASSWORD:
        st.stop()

maintenance_lock()

# =========================
# ⏱ RATE LIMITING
# =========================
def check_rate_limit():
    if "last_scan" not in st.session_state:
        st.session_state.last_scan = 0
    if time.time() - st.session_state.last_scan < 30:
        st.error("Please wait 30 seconds before scanning another paystub.")
        st.stop()
    st.session_state.last_scan = time.time()

# =========================
# 📦 FILE SIZE LIMIT
# =========================
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

# =========================
# 🧠 SAFE FLOAT PARSER
# =========================
def safe_float(val):
    try:
        return float(val)
    except:
        return 0.0

# =========================
# 🤖 MODEL DISCOVERY
# =========================
def get_best_model(api_key):
    url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    response = requests.get(url)
    if response.status_code != 200:
        return None, response.text
    models = response.json().get('models', [])
    valid = [m['name'] for m in models if 'generateContent' in m.get('supportedGenerationMethods', [])]
    return (valid[0].replace("models/", "") if valid else None), None

# =========================
# 🔍 AI PAYSTUB ANALYSIS
# =========================
def analyze_paystub_smart(image_bytes):
    api_key = st.secrets["GOOGLE_API_KEY"]
    model_name, error = get_best_model(api_key)
    if error or not model_name:
        return {"error": "Model discovery failed"}

    base64_image = base64.b64encode(image_bytes).decode('utf-8')
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"

    prompt_text = """Extract YTD totals and return ONLY raw JSON with:
    employee_name, employer_name, pay_period_end,
    ytd_overtime_income, ytd_double_time_income, ytd_tip_income"""

    payload = {
        "contents": [{
            "parts": [
                {"text": prompt_text},
                {"inline_data": {"mime_type": "image/jpeg", "data": base64_image}}
            ]
        }]
    }

    try:
        r = requests.post(url, headers={'Content-Type': 'application/json'}, json=payload)
        text = r.json()['candidates'][0]['content']['parts'][0]['text']
        clean = text.replace("```json", "").replace("```", "").strip()
        data = json.loads(clean)

        return {
            "employee_name": data.get("employee_name"),
            "employer_name": data.get("employer_name"),
            "pay_period_end": data.get("pay_period_end"),
            "ytd_overtime_income": safe_float(data.get("ytd_overtime_income")),
            "ytd_double_time_income": safe_float(data.get("ytd_double_time_income")),
            "ytd_tip_income": safe_float(data.get("ytd_tip_income")),
        }
    except:
        return {"error": "AI parsing failed"}

# =========================
# 📄 PDF GENERATOR
# =========================
def create_audit_pdf(data, ot_gross, dt_gross, tips, ot_exempt, dt_exempt, total_exempt, refund):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="Forensic Tax Audit Report (2025)", ln=True, align='C')
    pdf.set_font("Arial", size=12)
    pdf.ln(5)

    pdf.cell(200, 8, txt=f"Employee: {data.get('employee_name', 'Unknown')}", ln=True)
    pdf.cell(200, 8, txt=f"Employer: {data.get('employer_name', 'Unknown')}", ln=True)
    pdf.cell(200, 8, txt=f"Date: {data.get('pay_period_end', 'Unknown')}", ln=True)
    pdf.ln(10)

    pdf.cell(80, 10, "Income Type", 1)
    pdf.cell(50, 10, "Gross YTD", 1)
    pdf.cell(60, 10, "Tax-Exempt Portion", 1, ln=True)

    pdf.cell(80, 10, "Overtime (1.5x)", 1)
    pdf.cell(50, 10, f"${ot_gross:,.2f}", 1)
    pdf.cell(60, 10, f"${ot_exempt:,.2f}", 1, ln=True)

    pdf.cell(80, 10, "Double Time (2.0x)", 1)
    pdf.cell(50, 10, f"${dt_gross:,.2f}", 1)
    pdf.cell(60, 10, f"${dt_exempt:,.2f}", 1, ln=True)

    pdf.cell(80, 10, "Tips", 1)
    pdf.cell(50, 10, f"${tips:,.2f}", 1)
    pdf.cell(60, 10, f"${tips:,.2f}", 1, ln=True)

    pdf.cell(130, 10, "TOTAL DEDUCTIBLE INCOME", 1)
    pdf.cell(60, 10, f"${total_exempt:,.2f}", 1, ln=True)

    pdf.ln(5)
    pdf.cell(200, 10, txt=f"ESTIMATED REFUND INCREASE: ${refund:,.2f}", ln=True)

    return pdf.output(dest='S').encode('latin-1')

# =========================
# 💳 STRIPE PAYMENTS
# =========================
def create_stripe_session(ot_val, dt_val, tips_val):
    stripe.api_key = st.secrets["STRIPE_API_KEY"]
    BASE_URL = st.secrets["BASE_URL"]

    nonce = str(uuid.uuid4())
    fingerprint = f"{ot_val}|{dt_val}|{tips_val}|{nonce}"
    st.session_state['payment_nonce'] = nonce

    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price_data': {
                'currency': 'usd',
                'product_data': {'name': 'TaxShield Audit Report'},
                'unit_amount': 3999,
            },
            'quantity': 1,
        }],
        mode='payment',
        success_url=f'{BASE_URL}/?session_id={{CHECKOUT_SESSION_ID}}',
        cancel_url=f'{BASE_URL}/',
        metadata={'data_fingerprint': fingerprint}
    )
    return session.id, session.url

def check_payment_status(session_id, current_ot, current_dt, current_tips):
    stripe.api_key = st.secrets["STRIPE_API_KEY"]
    session = stripe.checkout.Session.retrieve(session_id)

    if session.payment_status != 'paid':
        return False

    stored = session.metadata.get('data_fingerprint', "")
    nonce = st.session_state.get("payment_nonce", "")
    current = f"{current_ot}|{current_dt}|{current_tips}|{nonce}"

    return stored == current

# =========================
# 🚀 MAIN APP
# =========================
st.title("🛡️ TaxShield365 Secure")

if 'paid' not in st.session_state:
    st.session_state['paid'] = False

uploaded_file = st.file_uploader("Upload Final 2025 Paystub", type=['png', 'jpg', 'jpeg'])

if uploaded_file:
    if uploaded_file.size > MAX_FILE_SIZE:
        st.error("File too large (max 5MB)")
        st.stop()

    check_rate_limit()

    with st.spinner("Analyzing paystub..."):
        data = analyze_paystub_smart(uploaded_file.getvalue())
        if "error" in data:
            st.error(data["error"])
        else:
            st.session_state['report_data'] = data

if 'report_data' in st.session_state:
    d = st.session_state['report_data']

    ot = st.number_input("Overtime YTD", value=d['ytd_overtime_income'])
    dt = st.number_input("Double Time YTD", value=d['ytd_double_time_income'])
    tips = st.number_input("Tips YTD", value=d['ytd_tip_income'])

    ot_ex = ot / 3
    dt_ex = dt / 4
    tips_cap = min(tips, 25000)
    total_ex = ot_ex + dt_ex + tips_cap
    refund = total_ex * 0.22

    st.metric("Total Tax-Exempt", f"${total_ex:,.2f}")
    st.metric("Estimated Refund Increase", f"${refund:,.2f}")

    if not st.session_state['paid']:
        if st.button("Unlock IRS Evidence Packet ($39.99)"):
            sid, url = create_stripe_session(ot, dt, tips_cap)
            st.session_state['stripe_session_id'] = sid
            st.markdown(f"[Click here to pay]({url})")

        if st.button("I Have Paid"):
            if check_payment_status(st.session_state['stripe_session_id'], ot, dt, tips_cap):
                st.session_state['paid'] = True
                st.success("Payment verified!")
            else:
                st.error("Payment not verified")

    if st.session_state['paid']:
        pdf = create_audit_pdf(d, ot, dt, tips_cap, ot_ex, dt_ex, total_ex, refund)
        st.download_button("Download IRS Evidence Packet", pdf, "TaxShield_Audit.pdf")

