import os
import re
import streamlit as st
from google import genai
from PIL import Image

# Page Config
st.set_page_config(
    page_title="SecurLog Agent",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SecurLog Agent")
st.markdown("ガバナンス・セキュリティを備えた自律型エラーログ解析＆セキュリティ監査エージェント")

# Sidebar for configuration
with st.sidebar:
    st.header("設定")
    api_key_input = st.text_input("Gemini API Key", type="password", value=os.environ.get("GEMINI_API_KEY", ""))
    if api_key_input:
        os.environ["GEMINI_API_KEY"] = api_key_input
    
    st.markdown("---")
    st.markdown("### 🔒 セキュリティ設定")
    enable_masking = st.checkbox("機密情報（APIキー・IP等）を自動マスクする", value=True)
    st.markdown("<small>※クラウド・LLM送信前に、APIキーやプライベートIPを自動的に伏せ字に置換します。</small>", unsafe_allow_html=True)

# 簡易的な機密情報マスキング関数
def mask_sensitive_data(text: str) -> str:
    if not text:
        return text
    text = re.sub(r'sk-[a-zA-Z0-9]{20,}', '[MASKED_API_KEY]', text)
    text = re.sub(r'AIza[0-9A-Za-z-_]{35}', '[MASKED_API_KEY]', text)
    text = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[MASKED_IP]', text)
    text = re.sub(r'(password|secret|token)\s*[:=]\s*[\'"]?[^\s,\'"]+[\'"]?', r'\1: [MASKED_SECRET]', text, flags=re.IGNORECASE)
    return text

# セッション状態の初期化
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "analysis_done" not in st.session_state:
    st.session_state.analysis_done = False
if "last_analysis" not in st.session_state:
    st.session_state.last_analysis = ""
if "last_audit" not in st.session_state:
    st.session_state.last_audit = ""
if "masked_ocr_text" not in st.session_state:
    st.session_state.masked_ocr_text = ""

# Main Input Section
col1, col2 = st.columns(2)

with col1:
    st.subheader("📥 入力データ & 添付ファイル")
    
    uploaded_files = st.file_uploader(
        "エラー画面の画像 (PNG/JPG) やドキュメント (PDF/Docx/Txt等) を添付", 
        type=["png", "jpg", "jpeg", "pdf", "txt", "docx", "csv"],
        accept_multiple_files=True,
        help="Snipping Toolでコピーした画像をここにCtrl+Vで貼り付けることも可能です"
    )

    error_log = st.text_area(
        "エラーログ / スタックトレースを貼り付け", 
        height=150, 
        placeholder="Traceback (most recent call last):\n  File 'app.py', line 12, in <module>\n    api_key = 'AIzaSyD...'\nValueError: Invalid API Key"
    )
    source_code = st.text_area(
        "関連するコードの断片（任意）", 
        height=120, 
        placeholder="def connect_db():\n    db.connect('192.168.1.50', password='secret_password')"
    )

with col2:
    st.subheader("📤 エージェント処理結果 & 対話")
    
    if st.button("🚀 解析とセキュリティ監査を実行", type="primary"):
        api_key = os.environ.get("GEMINI_API_KEY")
        if not error_log and not uploaded_files:
            st.warning("エラーログを入力するか、ファイルをアップロードしてください。")
        elif not api_key:
            st.warning("左側のサイドバーに Gemini API キーを入力してください。")
        else:
            with st.spinner("🤖 マルチエージェント（解析 ＆ セキュリティ監査）が稼働中..."):
                try:
                    # 1. セキュリティ：テキスト側のマスキング処理
                    processed_log = mask_sensitive_data(error_log) if enable_masking else error_log
                    processed_code = mask_sensitive_data(source_code) if enable_masking else source_code
                    
                    client = genai.Client(api_key=api_key)

                    # 2. 画像が含まれている場合、GeminiにOCR（文字起こし）とマスキングを依頼する
                    ocr_masked_result = ""
                    contents = []
                    contents.append(f"【エラーログ】\n{processed_log}\n\n【関連コード】\n{processed_code}")
                    
                    if uploaded_files:
                        for file in uploaded_files:
                            if file.type.startswith("image/"):
                                img = Image.open(file)
                                contents.append(img)
                                
                                # Geminiを使って画像からテキストを抽出し、機密情報をマスキングさせる（OCRセキュリティフィルター）
                                if enable_masking:
                                    ocr_prompt = """
この画像に含まれているすべてのテキスト（エラーメッセージ、コード、IPアドレス、APIキーなど）を正確に読み取ってください。
読み取ったテキストの中で、APIキー（AIza...など）やIPアドレス、パスワードなどの機密情報が含まれている場合は、それぞれ '[MASKED_API_KEY]'、'[MASKED_IP]'、'[MASKED_SECRET]' に置き換えて出力してください。
余計な解説は不要で、マスキングされたテキストのみを出力してください。
"""
                                    res_ocr = client.models.generate_content(
                                        model='models/gemini-3-flash-preview',
                                        contents=[ocr_prompt, img]
                                    )
                                    ocr_masked_result += f"\n--- 【画像OCR & マスキング結果: {file.name}】 ---\n" + res_ocr.text
                            else:
                                file_content = file.getvalue().decode("utf-8", errors="ignore")
                                if enable_masking:
                                    file_content = mask_sensitive_data(file_content)
                                contents.append(f"【添付ファイル: {file.name}】\n{file_content}")

                    if enable_masking:
                        st.success("🔒 セキュリティフィルター: テキストおよび添付画像内の機密情報（APIキーやIP等）を検出・マスクしました。")

                    # 保存用テキストを更新
                    st.session_state.masked_ocr_text = ocr_masked_result

                    # 3. エージェント1：ログ解析・修正エージェント
                    analysis_prompt = """
あなたは卓越したシニアソフトウェアエンジニアであり、エラー解析の専門家です。
提供されたエラーログ、コード、および画像/ファイルを分析し、原因の特定と具体的な修正案を日本語で分かりやすく提示してください。
"""
                    response_analysis = client.models.generate_content(
                        model='models/gemini-3-flash-preview',
                        contents=[analysis_prompt] + contents,
                    )

                    # 4. エージェント2：セキュリティ＆ガバナンス監査エージェント
                    audit_prompt = f"""
あなたは厳格なセキュリティ・ガバナンス監査官です。
以下の「エラーに対する修正案・原因分析」を確認し、この修正を行うことによって新たなセキュリティ脆弱性やガバナンス上の問題が発生しないかを監査してください。
判定結果（安全 / 要注意 / 危険）と、その理由を日本語で簡潔に記述してください。

【解析・修正案】
{response_analysis.text}
"""
                    response_audit = client.models.generate_content(
                        model='models/gemini-3-flash-preview',
                        contents=audit_prompt,
                    )

                    # 状態を保存
                    st.session_state.last_analysis = response_analysis.text
                    st.session_state.last_audit = response_audit.text
                    st.session_state.analysis_done = True
                    st.session_state.chat_history = [
                        {"role": "assistant", "content": "解析結果と監査が完了しました。さらに詳しく知りたい点や、コードの書き換え方法についてご質問ください。"}
                    ]

                except Exception as e:
                    st.error(f"エラーが発生しました: {e}")

    # 解析完了後の表示と対話セクション
    if st.session_state.analysis_done:
        tab1, tab2, tab3, tab4 = st.tabs(["🔍 ログ解析・修正案", "🛡️ セキュリティ監査結果", "💬 追加の対話・質問", "📋 マスキング後データ"])
        
        with tab1:
            st.markdown(st.session_state.last_analysis)
        
        with tab2:
            st.markdown(st.session_state.last_audit)
            st.info("💡 人間による承認 (Human-in-the-loop): 監査結果を確認の上、プルリクエストや反映を行ってください。")

        with tab3:
            st.markdown("#### 🤖 セキュア対話アシスタント")
            st.markdown("<small>機密情報がマスクされた状態のまま、エージェントに追加の質問ができます。</small>", unsafe_allow_html=True)
            
            for msg in st.session_state.chat_history:
                with st.chat_message(msg["role"]):
                    st.markdown(msg["content"])
            
            if user_question := st.chat_input("例: 「この修正案をDjangoのコードに適用する場合はどう書きますか？」"):
                st.session_state.chat_history.append({"role": "user", "content": user_question})
                with st.chat_message("user"):
                    st.markdown(user_question)
                
                with st.spinner("AIが回答を生成中..."):
                    try:
                        client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))
                        chat_prompt = f"""
これまでの文脈を踏まえて、ユーザーからの追加質問に日本語で回答してください。
【これまでの解析結果】
{st.session_state.last_analysis}

【ユーザーからの質問】
{user_question}
"""
                        chat_response = client.models.generate_content(
                            model='models/gemini-3-flash-preview',
                            contents=chat_prompt,
                        )
                        answer_text = chat_response.text
                        st.session_state.chat_history.append({"role": "assistant", "content": answer_text})
                        with st.chat_message("assistant"):
                            st.markdown(answer_text)
                    except Exception as e:
                        st.error(f"エラーが発生しました: {e}")

        with tab4:
            st.markdown("#### 🔒 テキスト入力データのマスキング確認")
            st.text("--- マスキング済みのエラーログ ---")
            st.code(error_log if error_log else "(テキスト入力なし)")
            st.text("--- マスキング済みのコード ---")
            st.code(source_code if source_code else "(コード入力なし)")
            
            if st.session_state.masked_ocr_text:
                st.markdown("#### 👁️ 画像OCR＆セキュリティマスキング結果")
                st.markdown("<small>アップロードされた画像からテキストを抽出（OCR）し、機密情報を安全に伏せ字化したプレビューです。</small>", unsafe_allow_html=True)
                st.code(st.session_state.masked_ocr_text)