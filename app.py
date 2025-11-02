import streamlit as st
import pandas as pd
import numpy as np

# إعداد الصفحة
st.set_page_config(
    page_title="تطبيق الذكاء الاصطناعي",
    page_icon="🚀",
    layout="wide"
)

# عنوان التطبيق
st.title("🎯 تطبيق التعلم الآلي")
st.write("التطبيق يعمل بنجاح!")

# تحميل بيانات بسيطة
@st.cache_data
def load_sample_data():
    return pd.DataFrame({
        'العمر': np.random.randint(18, 65, 100),
        'الدخل': np.random.randint(20000, 100000, 100),
        'النتيجة': np.random.randint(0, 2, 100)
    })

# عرض البيانات
data = load_sample_data()
st.subheader("عينة من البيانات")
st.dataframe(data.head(10))

# إحصاءات
st.subheader("الإحصاءات")
st.write(data.describe())

# رسم بياني بسيط
st.subheader("توزيع العمر")
st.bar_chart(data['العمر'].value_counts())

st.success("✅ التطبيق يعمل بشكل صحيح!")