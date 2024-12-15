from flask import Flask, request, jsonify
import pickle
from model import xgb_model_function
from model import rf_model_function
from model import model_top3_1_function
from model import combination_models_1_function
from model import probabilities_hm_1_function
from model import model_top3_3_function
from model import combination_models_3_function
from model import probabilities_hm_3_function
from model import nn_model_function
from model import cnn_model_function
from model import scaler_function
from model import all_classes_function
from model import scaler_cnn_function
import numpy as np
from model import label_encoder_integrated_function
import torch
import math

app = Flask(__name__)

# Load your trained model (example with pickle)
with open('model.pkl', 'rb') as f:
    model = pickle.load(f)

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.json
        X = data.get('features')
        if not X:
            return jsonify({"error": "No features provided"}), 400

        # Example: Process the incoming features to fit the model's expected input format
        # In this case, the feature_vector includes byte_value_histogram and byte_value_percentiles
        # feature_vector = [f['byte_value_histogram'] for f in features]  # Adjust this according to your feature set
        # feature_vector += [f['byte_value_percentiles'] for f in features]  # Add other features as needed
        
        
        import pandas as pd
        # Convert X to a pandas DataFrame (if it's not already)
        X = pd.DataFrame(X)

        X_cnn = X

        scaler = scaler_function()
        exclude_columns = ['mode', 'block_size', 'block_cipher_boolean', 'block_frequency', 
                        'length', 'byte_distribution_uniformity_score', 
                        'byte_distribution_low_frequency_byte_count', 
                        'byte_distribution_skewness', 'byte_distribution_kurtosis', 
                        'byte_distribution_dominant_byte_frequency', 'byte_distribution_byte_range_spread']

        # Find columns to scale
        columns_to_scale = X.columns.difference(exclude_columns)

        # Apply scaling
        X[columns_to_scale] = scaler.fit_transform(X[columns_to_scale])

        # # Convert X back to a list if necessary
        # X = X.values.tolist()

        #XGBoost
        xgb_model = xgb_model_function()
        node_features_xgb_sih = xgb_model.predict_proba(X)

        #Randomforest
        rf_model = rf_model_function()
        node_features_rf_sih = rf_model.predict_proba(X)

        #Hierarchial Model1
        model_top3_1 = model_top3_1_function()
        combination_models_1 = combination_models_1_function()
        probabilities_hm_1 = probabilities_hm_1_function()
        all_classes = all_classes_function()
        nodes_features_hm_1_sih = probabilities_hm_1(X, model_top3_1, combination_models_1, all_classes)

        #Hierarchial Model3
        model_top3_3 = model_top3_3_function()
        combination_models_3 = combination_models_3_function()
        probabilities_hm_3 = probabilities_hm_3_function()
        nodes_features_hm_3_sih = probabilities_hm_3(X, model_top3_3, combination_models_3, all_classes)

        #Neural Network
        nn_model = nn_model_function()
        node_features_nn_sih = nn_model.predict(X.to_numpy())

        #Convolution Neural Network(Method 1)
        scaler_cnn = scaler_cnn_function()
        X_normalized_cnn = scaler_cnn.transform(X_cnn)
        # y_test_cnn = y_test_cnn.astype(str)
        # y_test = y_test.flatten()
        # y_test = [y_test[i] for i in range(0, 2 * X_test.shape[0]) if (i % 2) == 1]
        # print(y_test_cnn)
        # print(len(y_test_cnn))
        # y_test_encoded_cnn = encoder.transform(y_test_cnn)
        # y_test_encoded = y_test_encoded[1]
        # Step 6: Reshape X_train into 10x11 images
        n_samples, n_features = X_normalized_cnn.shape
        n_rows = 10
        n_cols = 11  # We now have 110 features after padding
        # Pad if necessary (ensure 110 features)
        if n_features < n_rows * n_cols:
            padding = n_rows * n_cols - n_features
            X_normalized_cnn = np.pad(X_normalized_cnn, ((0, 0), (0, padding)), mode='constant', constant_values=0)
        X_images = X_normalized_cnn.reshape(n_samples, n_rows, n_cols, 1)

        # # Verify the shape of reshaped data
        # print("X_SIH_Testing_Dataset reshaped shape:", X_SIH_Testing_Dataset_images.shape)

        # # Step 7: Create a directory to save the images
        # output_dir = 'output_images/SIH_Testing_Dataset'
        # os.makedirs(output_dir, exist_ok=True)

        # # Step 8: Save each image as a PNG file
        # for i in range(n_samples):
        #     img = X_SIH_Testing_Dataset_images[i].reshape(n_rows, n_cols)  # Reshape to 10x11 for visualization
        #     plt.imshow(img, cmap='gray', interpolation='nearest')  # Display image in grayscale
        #     plt.axis('off')  # Turn off axis
        #     plt.savefig(f"{output_dir}/image_{i}.png", bbox_inches='tight', pad_inches=0)
        #     plt.close()  # Close the plot to avoid display

        # print(f"Images saved in {output_dir} directory.")
        cnn_model = cnn_model_function()
        node_features_cnn_sih = cnn_model.predict(X_images)

        node_features_sih = []
        batch_sih = []
        for i in range(0, len(X)):
            node_features_sih.append(node_features_xgb_sih[i])
            batch_sih.append(i)
            node_features_sih.append(node_features_rf_sih[i])
            batch_sih.append(i)
            node_features_sih.append(nodes_features_hm_1_sih[i])
            batch_sih.append(i)
            node_features_sih.append(nodes_features_hm_3_sih[i])
            batch_sih.append(i)
            node_features_sih.append(node_features_nn_sih[i])
            batch_sih.append(i)
            node_features_sih.append(node_features_cnn_sih[i])
            batch_sih.append(i)

        num_models = 6
        # Create a fully connected edge index for 6 nodes
        def create_fully_connected_edge_index(num_nodes):
            """
            Creates a fully connected edge index for a graph with num_nodes nodes.
            """
            edges = [(i, j) for i in range(num_nodes) for j in range(num_nodes) if i != j]
            edge_index = torch.tensor(edges, dtype=torch.long).t()  # Transpose to match PyTorch format
            return edge_index
        edge_index = create_fully_connected_edge_index(num_models)  # Fully connected graph

        from torch_geometric.data import Data
        # node_features_sih_array = np.array(node_features_sih)
        node_features_sih_tensor = torch.tensor(node_features_sih, dtype=torch.float32)
        batch_sih_tensor = torch.tensor(batch_sih, dtype=torch.long)

        x_data = Data(x=node_features_sih_tensor, edge_index=edge_index, batch=batch_sih_tensor)
        label_encoder_integrated = label_encoder_integrated_function()
        # Switch to evaluation mode
        model.eval()
        with torch.no_grad():
            probabilities = model(x_data.x, x_data.edge_index, x_data.batch)
            print(probabilities)
            prediction = probabilities.argmax(dim=1)
            print("Predicted classes:", prediction)
            print(prediction.shape)
            prediction = label_encoder_integrated.inverse_transform(prediction)
            print(prediction)
            print(type(prediction))
            probabilities = probabilities.tolist()
            for i in range(0, len(probabilities[0])):
                probabilities[0][i] = math.exp(probabilities[0][i])


        return jsonify({
            "prediction": prediction.tolist(),
            "probabilities": probabilities  # Return as list for easier parsing in Server 1
        })
    
    except Exception as e:
        print("Error occurred:", str(e))
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(port=5001)
