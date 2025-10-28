
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
warnings.filterwarnings('ignore')

def load_and_prepare_data(file_path):
    """Load and prepare the dataset"""
    try:
        df = pd.read_csv(file_path)
        print(f"Dataset loaded successfully: {df.shape}")
        print(f"Columns: {list(df.columns)}")
        return df
    except FileNotFoundError:
        print(f"File {file_path} not found. Please upload the dataset file.")
        # Create sample data for demonstration
        np.random.seed(42)
        n_samples = 1000
        data = {
            'dur': np.random.exponential(1, n_samples),
            'proto': np.random.choice(['tcp', 'udp', 'icmp'], n_samples),
            'service': np.random.choice(['http', 'ftp', 'smtp'], n_samples),
            'state': np.random.choice(['CON', 'FIN', 'REQ'], n_samples),
            'spkts': np.random.poisson(10, n_samples),
            'dpkts': np.random.poisson(8, n_samples),
            'sbytes': np.random.exponential(100, n_samples),
            'dbytes': np.random.exponential(80, n_samples),
            'sttl': np.random.randint(0, 255, n_samples),
            'dttl': np.random.randint(0, 255, n_samples),
            'attack_cat': np.random.choice(['Normal', 'DoS', 'Probe', 'R2L', 'U2R'], 
                                         n_samples, p=[0.8, 0.1, 0.05, 0.03, 0.02])
        }
        df = pd.DataFrame(data)
        print("Using sample dataset for demonstration")
        return df

def preprocess_data(df):
    """Clean and preprocess the data"""
    # Handle categorical variables
    label_encoders = {}
    categorical_columns = df.select_dtypes(include=['object']).columns
    
    for col in categorical_columns:
        if col != 'attack_cat':  # Don't encode the target variable yet
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            label_encoders[col] = le
    
    # Fill missing values
    df = df.fillna(0)
    
    # Separate features and target
    if 'attack_cat' in df.columns:
        target_col = 'attack_cat'
        X = df.drop(target_col, axis=1)
        y = df[target_col]
    elif 'Label' in df.columns:
        target_col = 'Label'
        X = df.drop(target_col, axis=1)
        y = df[target_col]
    else:
        # If no clear target column, use all numeric features
        X = df.select_dtypes(include=[np.number])
        y = None
    
    return X, y, label_encoders

def detect_anomalies_isolation_forest(X, contamination=0.05):
    """Detect anomalies using Isolation Forest"""
    print("\n=== Isolation Forest Anomaly Detection ===")
    
    # Scale the features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Train Isolation Forest
    iso_forest = IsolationForest(contamination=contamination, random_state=42, n_estimators=100)
    anomaly_predictions = iso_forest.fit_predict(X_scaled)
    
    # Convert predictions (-1 for anomaly, 1 for normal)
    anomaly_labels = np.where(anomaly_predictions == -1, 'Suspicious', 'Normal')
    
    # Print results
    unique, counts = np.unique(anomaly_labels, return_counts=True)
    print(f"Detection Results:")
    for label, count in zip(unique, counts):
        percentage = (count / len(anomaly_labels)) * 100
        print(f"  {label}: {count} ({percentage:.2f}%)")
    
    return anomaly_predictions, anomaly_labels, scaler, iso_forest

def supervised_classification(X, y):
    """Perform supervised classification if labels are available"""
    if y is None:
        print("\nNo labels available for supervised learning")
        return None, None, None, None
    
    print("\n=== Supervised Classification Comparison ===")
    
    # Encode target variable
    le_target = LabelEncoder()
    y_encoded = le_target.fit_transform(y)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Initialize models for comparison
    from sklearn.svm import SVC
    from sklearn.naive_bayes import GaussianNB
    from sklearn.linear_model import LogisticRegression
    
    models = {
        'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
        'SVM': SVC(kernel='rbf', random_state=42),
        'Logistic Regression': LogisticRegression(random_state=42, max_iter=1000),
        'Naive Bayes': GaussianNB()
    }
    
    results = {}
    best_model = None
    best_score = 0
    
    print("\nModel Comparison Results:")
    print("-" * 60)
    
    for name, model in models.items():
        # Train model
        model.fit(X_train_scaled, y_train)
        y_pred = model.predict(X_test_scaled)
        
        # Calculate metrics
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, average='weighted')
        recall = recall_score(y_test, y_pred, average='weighted')
        f1 = f1_score(y_test, y_pred, average='weighted')
        
        results[name] = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'model': model,
            'predictions': y_pred
        }
        
        print(f"{name:20} | Acc: {accuracy:.3f} | Prec: {precision:.3f} | Rec: {recall:.3f} | F1: {f1:.3f}")
        
        # Track best model
        if f1 > best_score:
            best_score = f1
            best_model = (name, model, y_pred)
    
    print(f"\nBest Model: {best_model[0]} (F1-Score: {best_score:.3f})")
    
    # Detailed report for best model
    print(f"\nDetailed Classification Report for {best_model[0]}:")
    target_names = le_target.classes_
    print(classification_report(y_test, best_model[2], target_names=target_names))
    
    return best_model[1], scaler, le_target, (X_test, y_test, best_model[2]), results

def visualize_results(anomaly_labels, y_true=None, y_pred=None):
    """Create visualizations of the results"""
    plt.figure(figsize=(15, 5))
    
    # Plot 1: Anomaly Detection Results
    plt.subplot(1, 3, 1)
    unique, counts = np.unique(anomaly_labels, return_counts=True)
    colors = ['lightgreen' if label == 'Normal' else 'lightcoral' for label in unique]
    plt.pie(counts, labels=unique, autopct='%1.1f%%', colors=colors)
    plt.title('Anomaly Detection Results\n(Isolation Forest)')
    
    # Plot 2: Feature Importance (if supervised model available)
    if y_true is not None:
        plt.subplot(1, 3, 2)
        unique_true, counts_true = np.unique(y_true, return_counts=True)
        plt.bar(range(len(unique_true)), counts_true, color='skyblue')
        plt.xlabel('Attack Categories')
        plt.ylabel('Count')
        plt.title('True Label Distribution')
        plt.xticks(range(len(unique_true)), unique_true, rotation=45)
    
    # Plot 3: Comparison if both available
    if y_pred is not None:
        plt.subplot(1, 3, 3)
        cm = confusion_matrix(y_true, y_pred)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.title('Confusion Matrix\n(Supervised Classification)')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
    
    plt.tight_layout()
    plt.savefig('detection_results.png', dpi=300, bbox_inches='tight')
    plt.show()
    print("\nVisualization saved as 'detection_results.png'")

def main():
    """Main function to run the zero-day attack detection system"""
    print("🔒 Zero-Day Attack Detection System")
    print("=" * 50)
    
    # Try to load different common dataset names
    dataset_files = ['UNSW-NB15.csv', 'CICIDS2017.csv', 'dataset.csv', 'data.csv']
    df = None
    
    for file_path in dataset_files:
        df = load_and_prepare_data(file_path)
        if df is not None:
            break
    
    if df is None:
        print("No dataset found. Please upload your dataset file.")
        return
    
    # Preprocess data
    X, y, label_encoders = preprocess_data(df)
    print(f"\nPreprocessed data shape: {X.shape}")
    
    # Anomaly Detection using Isolation Forest
    anomaly_pred, anomaly_labels, iso_scaler, iso_model = detect_anomalies_isolation_forest(X)
    
    # Supervised Classification (if labels available)
    rf_model, rf_scaler, le_target, test_results = supervised_classification(X, y)
    
    # Visualizations
    if test_results:
        X_test, y_test, y_pred = test_results
        visualize_results(anomaly_labels, y_test, y_pred)
    else:
        visualize_results(anomaly_labels)
    
    # Save results
    results_df = X.copy()
    results_df['anomaly_prediction'] = anomaly_labels
    results_df['anomaly_score'] = anomaly_pred
    
    if y is not None:
        results_df['true_label'] = y
    
    results_df.to_csv('detection_results.csv', index=False)
    print(f"\nResults saved to 'detection_results.csv'")
    
    # Generate comprehensive research report
    try:
        from generate_report import generate_research_report, create_performance_visualizations
        
        # Generate report
        if test_results and 'results' in locals():
            report = generate_research_report(anomaly_labels, test_results, results)
            create_performance_visualizations(results)
        else:
            report = generate_research_report(anomaly_labels, test_results)
        
        print("📄 Research report generated successfully!")
    except Exception as e:
        print(f"Report generation failed: {e}")
    
    print("\n🎯 Detection Complete!")
    print("📁 Files generated:")
    print("  - detection_results.csv (البيانات والنتائج)")
    print("  - detection_results.png (المخططات)")
    print("  - research_report.md (تقرير البحث)")
    print("  - model_comparison.png (مقارنة النماذج)")
    print("\n💡 لتشغيل لوحة التحكم التفاعلية:")
    print("  streamlit run app.py")
    print("\nUpload your dataset (UNSW-NB15.csv or CICIDS2017.csv) for better results.")

if __name__ == "__main__":
    main()
