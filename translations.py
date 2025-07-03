from flask import session, request, current_app

def get_locale():
    # Check if language is in URL
    path_parts = [p for p in request.path.strip('/').split('/') if p]
    if path_parts and path_parts[0] in current_app.config['LANGUAGES']:
        lang = path_parts[0]
        session['language'] = lang
        return lang
    
    # Check if language is in session
    if 'language' in session and session['language'] in current_app.config['LANGUAGES']:
        return session['language']
    
    # Check if language is in cookie
    cookie_lang = request.cookies.get('language')
    if cookie_lang and cookie_lang in current_app.config['LANGUAGES']:
        session['language'] = cookie_lang
        return cookie_lang
    
    # Try to get language from browser settings
    browser_lang = request.accept_languages.best_match(current_app.config['LANGUAGES'].keys())
    if browser_lang:
        session['language'] = browser_lang
        return browser_lang
    
    # Default to Thai
    session['language'] = 'th'
    return 'th'

# Translation dictionaries (kept for backward compatibility)
TRANSLATIONS = {
    'en': {
        'login': 'Login',
        'username': 'Username',
        'password': 'Password',
        'confirm_password': 'Confirm Password',
        'role': 'Role',
        'doctor': '👨\u200d⚕️ Doctor',
        'patient': '👤 Patient',
        'submit': 'Login',
        'select_role': 'Select Role',
        'welcome': 'Welcome to Medicine Management System',
        'dont_have_account': "Don't have an account?",
        'register': 'Register',
        'processing': 'Processing...',
        'please_enter_your_username': 'Please enter your username',
        'username_length_validation': 'Username must be between 3-80 characters',
        'please_enter_your_password': 'Please enter your password',
        'password_length_validation': 'Password must be at least 6 characters',
        'select_role': 'Select Role',
        'please_select_role': 'Please select a role',
        'please_enter_your_credentials': 'Please enter your credentials to log in',
        'please_fill_in_all_fields': 'Please fill in all required fields',
        'name': 'Full Name',
        'email': 'Email',
        'phone': 'Phone Number',
        'back_to_home': 'Back to Home',
        'patient_system': 'Patient System',
        'patient_registration': 'Patient Registration',
        'register_to_get_medicine': 'Register to get medicine',
        'age': 'Age',
        'gender': 'Gender',
        'select_gender': 'Select Gender',
        'male': 'Male',
        'female': 'Female',
        'phone_number': 'Phone Number',
        'symptoms': 'Symptoms',
        'allergy_history': 'Allergy History',
        'please_wait_for_medicine': 'Please wait for your medicine',
        'processing_your_request': 'We are processing your request, please wait...',
        'loading': 'Loading',
        'medicine_ready': 'Medicine Ready',
        'please_show_qr_code': 'Please show this QR code at the counter',
        'waiting_for_prescription': 'Waiting for Prescription',
        'prescription_ready': 'Prescription Ready',
        'prescription_ready_message': 'Your prescription is ready!',
        'show_qr_code': 'Show QR Code',
        'patient_info': 'Patient Information',
        'waiting_time': 'Estimated waiting time',
        'minutes': 'minutes',
        'error_occurred': 'An error occurred',
        'please_wait': 'Please wait',
        'prescription_processing': 'Processing your prescription...'
    },
    'th': {
        'login': 'เข้าสู่ระบบ',
        'username': 'ชื่อผู้ใช้',
        'password': 'รหัสผ่าน',
        'confirm_password': 'ยืนยันรหัสผ่าน',
        'role': 'บทบาท',
        'doctor': '👨\u200d⚕️ แพทย์',
        'patient': '👤 ผู้ป่วย',
        'submit': 'เข้าสู่ระบบ',
        'select_role': 'เลือกบทบาท',
        'welcome': 'ยินดีต้อนรับสู่ระบบจัดการยา',
        'dont_have_account': 'ยังไม่มีบัญชีผู้ใช้?',
        'register': 'สมัครสมาชิก',
        'processing': 'กำลังดำเนินการ...',
        'please_enter_your_username': 'กรุณากรอกชื่อผู้ใช้',
        'username_length_validation': 'ชื่อผู้ใช้ต้องมีความยาวระหว่าง 3-80 ตัวอักษร',
        'please_enter_your_password': 'กรุณากรอกรหัสผ่าน',
        'password_length_validation': 'รหัสผ่านต้องมีความยาวอย่างน้อย 6 ตัวอักษร',
        'select_role': 'เลือกบทบาท',
        'please_select_role': 'กรุณาเลือกบทบาท',
        'please_enter_your_credentials': 'กรุณากรอกข้อมูลเพื่อเข้าสู่ระบบ',
        'please_fill_in_all_fields': 'กรุณากรอกข้อมูลให้ครบถ้วน',
        'name': 'ชื่อ-นามสกุล',
        'email': 'อีเมล',
        'phone': 'เบอร์โทรศัพท์',
        'back_to_home': 'กลับหน้าหลัก',
        'patient_system': 'ระบบจัดการคนไข้',
        'patient_registration': 'ระบบลงทะเบียนคนไข้',
        'register_to_get_medicine': 'ลงทะเบียนเพื่อรับยา',
        'age': 'อายุ',
        'gender': 'เพศ',
        'select_gender': 'เลือกเพศ',
        'male': 'ชาย',
        'female': 'หญิง',
        'phone_number': 'เบอร์โทรศัพท์',
        'symptoms': 'อาการเบื้องต้น',
        'allergy_history': 'ประวัติการแพ้ยา',
        'please_wait_for_medicine': 'กรุณารอรับยา',
        'processing_your_request': 'ระบบกำลังประมวลผลข้อมูลของคุณ โปรดรอสักครู่',
        'loading': 'กำลังโหลด',
        'medicine_ready': 'ยาพร้อมจ่าย',
        'please_show_qr_code': 'กรุณานำ QR Code นี้ไปที่เคาน์เตอร์รับยา',
        'waiting_for_prescription': 'รอใบสั่งยา',
        'prescription_ready': 'ใบสั่งยาพร้อมแล้ว',
        'prescription_ready_message': 'ใบสั่งยาของคุณพร้อมแล้ว!',
        'show_qr_code': 'แสดง QR Code',
        'patient_info': 'ข้อมูลผู้ป่วย',
        'waiting_time': 'เวลารอโดยประมาณ',
        'minutes': 'นาที',
        'error_occurred': 'เกิดข้อผิดพลาด',
        'please_wait': 'กรุณารอสักครู่',
        'prescription_processing': 'กำลังประมวลผลใบสั่งยา...'
    },
    'ja': {
        'login': 'ログイン',
        'username': 'ユーザー名',
        'password': 'パスワード',
        'confirm_password': 'パスワード確認',
        'role': '役割',
        'doctor': '👨\u200d⚕️ 医者',
        'patient': '👤 患者',
        'submit': 'ログイン',
        'select_role': '役割を選択',
        'welcome': '薬管理システムへようこそ',
        'dont_have_account': 'アカウントをお持ちでない場合',
        'register': '登録',
        'processing': '処理中...',
        'please_enter_your_username': 'ユーザー名を入力してください',
        'username_length_validation': 'ユーザー名は3〜80文字で入力してください',
        'please_enter_your_password': 'パスワードを入力してください',
        'password_length_validation': 'パスワードは6文字以上で入力してください',
        'select_role': '役割を選択',
        'please_select_role': '役割を選択してください',
        'please_enter_your_credentials': 'ログインするには認証情報を入力してください',
        'please_fill_in_all_fields': 'すべての必須項目に入力してください',
        'name': '氏名',
        'email': 'メールアドレス',
        'phone': '電話番号',
        'back_to_home': 'ホームに戻る',
        'patient_system': '患者システム',
        'patient_registration': '患者登録',
        'register_to_get_medicine': '薬を受け取るために登録する',
        'age': '年齢',
        'gender': '性別',
        'select_gender': '性別を選択',
        'male': '男性',
        'female': '女性',
        'phone_number': '電話番号',
        'symptoms': '症状',
        'allergy_history': 'アレルギー歴',
        'please_wait_for_medicine': '薬をお待ちください',
        'processing_your_request': 'リクエストを処理中です。少々お待ちください...',
        'loading': '読み込み中',
        'medicine_ready': '薬の準備ができました',
        'please_show_qr_code': 'カウンターでこのQRコードを提示してください',
        'waiting_for_prescription': '処方箋待ち',
        'prescription_ready': '処方箋の準備が完了しました',
        'prescription_ready_message': '処方箋の準備ができました！',
        'show_qr_code': 'QRコードを表示',
        'patient_info': '患者情報',
        'waiting_time': 'おおよその待ち時間',
        'minutes': '分',
        'error_occurred': 'エラーが発生しました',
        'please_wait': '少々お待ちください',
        'prescription_processing': '処方箋を処理中です...'
    }
}

def translate(key, lang=None):
    """Get translation for a key in the specified language"""
    if lang is None:
        lang = get_locale()
    return TRANSLATIONS.get(lang, {}).get(key, key)
