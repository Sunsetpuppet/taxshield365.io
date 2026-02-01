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
    
    # SECURITY UPGRADE:
