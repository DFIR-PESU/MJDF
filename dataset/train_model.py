import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib


dataset_path = r"C:\Users\Sameeksha J S\Downloads\combined_dataset.csv"
df = pd.read_csv(dataset_path)

print(df.head())


X = df.drop('Label', axis=1)  # Features
y = df['Label']               # Target variable


X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

rf_model = RandomForestClassifier(random_state=42)
rf_model.fit(X_train, y_train)

y_train_pred = rf_model.predict(X_train)
y_test_pred = rf_model.predict(X_test)


train_accuracy = accuracy_score(y_train, y_train_pred)
test_accuracy = accuracy_score(y_test, y_test_pred)

print(f"Training Accuracy: {train_accuracy}")
print(f"Testing Accuracy: {test_accuracy}")

#replace the path 

model_path = r"C:\Users\Sameeksha J S\Downloads\random_forest_model.joblib"
joblib.dump(rf_model, model_path)

loaded_model = joblib.load(model_path)

new_predictions = loaded_model.predict(X_test)


loaded_model_accuracy = accuracy_score(y_test, new_predictions)
print(f"Loaded Model Testing Accuracy: {loaded_model_accuracy}")