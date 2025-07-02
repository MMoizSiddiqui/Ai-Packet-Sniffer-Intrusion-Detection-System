# model/train.py
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder, OneHotEncoder
from sklearn.compose import ColumnTransformer
import tensorflow as tf
import pickle
import os

# Define column names
cols = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
    'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
    'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
    'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label'
]

print("Loading training data...")
df = pd.read_csv('data/KDDTrain.csv', names=cols, nrows=10000)

# Convert label to binary (0 for normal, 1 for attack)
label_encoder = LabelEncoder()
y = label_encoder.fit_transform(df['label'].apply(lambda x: 0 if x == 'normal.' else 1))
X = df.drop('label', axis=1)

# Identify categorical and numerical columns
categorical_features = ['protocol_type', 'flag']
label_encode_features = ['service']
numerical_features = [col for col in X.columns if col not in categorical_features + label_encode_features]

# Label encode 'service'
le_service = LabelEncoder()
X['service'] = le_service.fit_transform(X['service'])

# Convert numerical columns to float
for col in numerical_features:
    X[col] = pd.to_numeric(X[col], errors='coerce')
    X[col] = X[col].fillna(0)

# Create preprocessing steps
preprocessor = ColumnTransformer(
    transformers=[
        ('num', StandardScaler(), numerical_features + label_encode_features),
        ('cat', OneHotEncoder(sparse_output=False, handle_unknown='ignore'), categorical_features)
    ]
)

# Fit and transform the data
print("Preprocessing data...")
X_transformed = preprocessor.fit_transform(X)

# Split the data
print("Splitting data...")
X_train, X_val, y_train, y_val = train_test_split(X_transformed, y, test_size=0.2, random_state=42)

# Save the preprocessor and label encoder for service
print("Saving preprocessor and label encoder...")
os.makedirs('model', exist_ok=True)
with open('model/preprocessor.pkl', 'wb') as f:
    pickle.dump(preprocessor, f)
with open('model/service_label_encoder.pkl', 'wb') as f:
    pickle.dump(le_service, f)

# Build the model
print("Building model...")
model = tf.keras.Sequential([
    tf.keras.layers.Dense(64, activation='relu', input_shape=(X_transformed.shape[1],)),
    tf.keras.layers.Dropout(0.3),
    tf.keras.layers.Dense(32, activation='relu'),
    tf.keras.layers.Dropout(0.2),
    tf.keras.layers.Dense(1, activation='sigmoid')
])

# Compile the model
model.compile(optimizer='adam',
              loss='binary_crossentropy',
              metrics=['accuracy'])

# Train the model
print("Training model...")
history = model.fit(
    X_train, y_train,
    epochs=10,
    batch_size=32,
    validation_data=(X_val, y_val),
    verbose=1
)

# Save the model weights
print("Saving model...")
model.save('model/model_weights.h5')

print("Training completed successfully!")
