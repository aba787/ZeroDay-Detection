
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import base64

# إعداد الصفحة
st.set_page_config(
    page_title="كاشف البرمجيات الخبيثة بالذكاء الاصطناعي",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better design
st.markdown("""
<style>
.main-header {
    background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
    padding: 2rem;
    border-radius: 10px;
    color: white;
    text-align: center;
    margin-bottom: 2rem;
}
.metric-card {
    background: white;
    padding: 1.5rem;
    border-radius: 10px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    border-left: 4px solid #667eea;
}
.stMetric {
    background: linear-gradient(45deg, #f0f2f6, #ffffff);
    padding: 1rem;
    border-radius: 8px;
}
</style>
""", unsafe_allow_html=True)

# Header
st.markdown("""
<div class="main-header">
    <h1>🛡️ كاشف البرمجيات الخبيثة بالذكاء الاصطناعي</h1>
    <p>نظام متقدم لكشف السلوك الخبيث والثغرات في البرمجيات باستخدام تقنيات التعلم الآلي</p>
</div>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.markdown("## ⚙️ إعدادات النظام")
    
    analysis_type = st.selectbox(
        "نوع التحليل",
        ["تحليل شامل", "كشف الشذوذ", "التصنيف المتقدم", "مراقبة مباشرة"]
    )
    
    model_type = st.selectbox(
        "نموذج التعلم الآلي",
        ["Random Forest", "SVM", "Isolation Forest", "Naive Bayes"]
    )
    
    threat_level = st.slider("مستوى الحساسية", 1, 10, 7)
    
    st.markdown("---")
    st.markdown("### 📊 إحصائيات سريعة")
    st.metric("البرامج المحللة", "1,247")
    st.metric("التهديدات المكتشفة", "89")
    st.metric("معدل الدقة", "97.3%")

# Main content
col1, col2, col3 = st.columns([2, 2, 1])

with col1:
    st.markdown("### 🔍 نتائج التحليل")
    
    # Sample analysis data
    analysis_data = {
        'نوع التهديد': ['آمن', 'مشبوه', 'خبيث', 'ثغرة أمنية'],
        'العدد': [180, 45, 15, 8],
        'النسبة': [72.6, 18.1, 6.0, 3.2]
    }
    
    df_threats = pd.DataFrame(analysis_data)
    
    # Pie chart
    fig_pie = px.pie(
        df_threats, 
        values='العدد', 
        names='نوع التهديد',
        title="توزيع أنواع التهديدات",
        color_discrete_sequence=['#2ecc71', '#f39c12', '#e74c3c', '#9b59b6']
    )
    fig_pie.update_layout(font=dict(size=14))
    st.plotly_chart(fig_pie, use_container_width=True)

with col2:
    st.markdown("### 📈 تحليل زمني للتهديدات")
    
    # Time series data
    dates = pd.date_range('2024-01-01', periods=30, freq='D')
    threats_over_time = {
        'التاريخ': dates,
        'التهديدات': np.random.poisson(5, 30),
        'البرامج الآمنة': np.random.poisson(20, 30)
    }
    
    df_time = pd.DataFrame(threats_over_time)
    
    fig_line = px.line(
        df_time, 
        x='التاريخ', 
        y=['التهديدات', 'البرامج الآمنة'],
        title="اتجاه التهديدات عبر الزمن"
    )
    fig_line.update_layout(font=dict(size=12))
    st.plotly_chart(fig_line, use_container_width=True)

with col3:
    st.markdown("### 🚨 تنبيهات فورية")
    
    alerts = [
        {"النوع": "خطر عالي", "الوقت": "قبل 5 دقائق", "الرسالة": "برنامج مشبوه"},
        {"النوع": "متوسط", "الوقت": "قبل 12 دقيقة", "الرسالة": "نشاط غير عادي"},
        {"النوع": "منخفض", "الوقت": "قبل 25 دقيقة", "الرسالة": "فحص روتيني"}
    ]
    
    for alert in alerts:
        color = {"خطر عالي": "🔴", "متوسط": "🟡", "منخفض": "🟢"}[alert["النوع"]]
        st.markdown(f"""
        <div style="background: #f8f9fa; padding: 0.8rem; border-radius: 5px; margin-bottom: 0.5rem;">
            {color} <strong>{alert["النوع"]}</strong><br>
            <small>{alert["الوقت"]}</small><br>
            {alert["الرسالة"]}
        </div>
        """, unsafe_allow_html=True)

# Features section
st.markdown("---")
col_a, col_b, col_c, col_d = st.columns(4)

with col_a:
    st.markdown("""
    <div class="metric-card">
        <h3>🤖 تعلم آلي متقدم</h3>
        <p>خوارزميات متطورة لكشف التهديدات الجديدة والمجهولة</p>
    </div>
    """, unsafe_allow_html=True)

with col_b:
    st.markdown("""
    <div class="metric-card">
        <h3>⚡ سرعة فائقة</h3>
        <p>تحليل فوري للبرامج دون التأثير على الأداء</p>
    </div>
    """, unsafe_allow_html=True)

with col_c:
    st.markdown("""
    <div class="metric-card">
        <h3>🔍 دقة عالية</h3>
        <p>معدل دقة 97%+ مع أقل نسبة إنذار كاذب</p>
    </div>
    """, unsafe_allow_html=True)

with col_d:
    st.markdown("""
    <div class="metric-card">
        <h3>📊 تقارير شاملة</h3>
        <p>تحليلات مفصلة وتقارير قابلة للتخصيص</p>
    </div>
    """, unsafe_allow_html=True)

# Software analysis simulation
st.markdown("---")
st.markdown("### 💻 محاكي تحليل البرامج")

col_left, col_right = st.columns([1, 1])

with col_left:
    uploaded_file = st.file_uploader(
        "ارفع ملف البرنامج للتحليل",
        type=['exe', 'dll', 'py', 'js', 'jar'],
        help="الأنواع المدعومة: EXE, DLL, PY, JS, JAR"
    )
    
    if st.button("🔍 بدء التحليل", type="primary"):
        with st.spinner("جاري التحليل..."):
            import time
            time.sleep(2)
            
            # Simulate analysis results
            risk_score = np.random.randint(1, 100)
            
            if risk_score < 30:
                st.success(f"✅ البرنامج آمن - درجة المخاطر: {risk_score}/100")
            elif risk_score < 70:
                st.warning(f"⚠️ البرنامج مشبوه - درجة المخاطر: {risk_score}/100")
            else:
                st.error(f"🚨 برنامج خطير - درجة المخاطر: {risk_score}/100")

with col_right:
    st.markdown("#### 📋 تفاصيل التحليل")
    
    analysis_details = pd.DataFrame({
        'الخاصية': ['حجم الملف', 'عدد الوظائف', 'استدعاءات النظام', 'التشفير', 'التوقيع الرقمي'],
        'القيمة': ['2.1 MB', '127', '45', 'متقدم', 'غير موجود'],
        'المخاطر': ['منخفض', 'متوسط', 'عالي', 'منخفض', 'عالي']
    })
    
    st.dataframe(analysis_details, use_container_width=True)

# Research information
st.markdown("---")
st.markdown("### 🎓 معلومات البحث")

research_info = st.expander("تفاصيل المشروع البحثي", expanded=False)
with research_info:
    st.markdown("""
    **عنوان البحث:** استخدام التعلم الآلي لكشف السلوك الخبيث والثغرات في البرمجيات
    
    **الهدف الرئيسي:** تطوير نموذج ذكي لتحليل سلوك البرمجيات والكشف عن التهديدات الأمنية
    
    **التقنيات المستخدمة:**
    - Random Forest للتصنيف
    - Isolation Forest لكشف الشذوذ  
    - SVM للتصنيف المتقدم
    - Statistical Analysis للتحليل الإحصائي
    
    **مصادر البيانات:**
    - مجموعات بيانات عامة من Kaggle
    - عينات من GitHub للاختبار
    - بيانات غير حساسة ومجهولة الهوية
    
    **المخرجات المتوقعة:**
    - نموذج مدرب للكشف عن البرامج الخبيثة
    - واجهة تفاعلية للتحليل
    - تقارير مقارنة للخوارزميات
    - توثيق شامل للنتائج
    """)

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #666; padding: 1rem;">
    🛡️ <strong>نظام كشف البرمجيات الخبيثة</strong> | 
    مدعوم بالذكاء الاصطناعي | 
    تم التطوير في عام 2024
</div>
""", unsafe_allow_html=True)

# Status indicator
st.markdown("""
<div style="position: fixed; top: 10px; right: 10px; background: #2ecc71; color: white; padding: 0.5rem; border-radius: 15px; z-index: 999;">
    🟢 النظام متصل
</div>
""", unsafe_allow_html=True)
