import os

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer

# ... Load xss_payloads and non_xss_payloads ...
xss_payloads = []
non_xss_payloads = []

# ... Loading data ...
# (Code to load xss_payloads and non_xss_payloads)
file_path = r'D:\PROJECTS\SCHOOL\Yr2_sem2\IT2566_ispj\ISPJ_PROJ\Sentinel_api\SentinelSuite\directory_traversal\directory_traversal.txt'
with open(file_path, 'r', encoding='utf-8') as file:
    lines = file.readlines()

    for line in lines:
        xss_payloads.append(line.strip())

non_payload_path = r'D:\PROJECTS\SCHOOL\Yr2_sem2\IT2566_ispj\ISPJ_PROJ\Sentinel_api\SentinelSuite\non_traversal_payloads.txt'
with open(non_payload_path, 'r') as file:
    for line in file.readlines():
        non_xss_payloads.append(line.strip())

# Use TF-IDF Vectorizer with min_df and max_features
vectorizer = TfidfVectorizer(ngram_range=(1, 3), min_df=5, max_features=400, sublinear_tf=True)
X = vectorizer.fit_transform(xss_payloads + non_xss_payloads)
y = [1] * len(xss_payloads) + [0] * len(non_xss_payloads)

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train the model
model = RandomForestClassifier(n_estimators=100, max_depth=None, random_state=42)
model.fit(X_train, y_train)

# Make predictions on the test set
y_pred = model.predict(X_test)

# Calculate accuracy
accuracy = accuracy_score(y_test, y_pred)
# print(f'Accuracy: {accuracy * 100:.2f}%')

# Now use the model to predict
def is_traversal(payload):
    payload_features = vectorizer.transform([payload])
    prediction = model.predict(payload_features)
    return bool(prediction[0])

# payload = 'http://127.0.0.1:/login/dashboard?url=asd'
# result = is_traversal(payload)
# payload2 = 'http://127.0.0.1/../../etc/passwd'
# result2 = is_traversal(payload2)
# print(f'Is directory traversal: {result}')
# print(f'Is directory traversal: {result2}')