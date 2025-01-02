# train_model.py
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib

# Load and preprocess data
file_path = 'E:/VS Python/Email_folder/Phishing_Email.csv'
df = pd.read_csv(file_path)
df_cleaned = df.dropna(subset=['Email Text']).copy()
df_cleaned['Email Type'] = df_cleaned['Email Type'].map({'Safe Email': 0, 'Phishing Email': 1})
df_cleaned['Email Type'] = df_cleaned['Email Type'].astype(int)

# Feature extraction
tfidf_vectorizer = TfidfVectorizer(max_features=3000)
X = tfidf_vectorizer.fit_transform(df_cleaned['Email Text']).toarray()
y = df_cleaned['Email Type']

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
random_forest_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
random_forest_classifier.fit(X_train, y_train)

# Evaluate
y_pred = random_forest_classifier.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy:.4f}")
print("\nClassification Report:\n", classification_report(y_test, y_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))

# Save the model and vectorizer
joblib.dump(random_forest_classifier, 'phishing_email_detection/models/random_forest_classifier.joblib') 
joblib.dump(tfidf_vectorizer, 'phishing_email_detection/models/tfidf_vectorizer.joblib')
