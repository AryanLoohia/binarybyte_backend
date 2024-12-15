"use client"
import React, { useState } from "react";
import axios from "axios";
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend } from "chart.js";
import { Bar } from "react-chartjs-2";

type result = {
  original: string;
  error?: string; // optional property
  prediction: string[];
  probabilities: number[];
  class_labels: string[];
  sorted_probabilities: number[];
  
};

// Register Chart.js components
ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

export default function HexPrediction() {
  const [inputType, setInputType] = useState("text"); // "text", "file"
  const [hexData, setHexData] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [fileType, setFileType] = useState("text"); // "text", "csv", "xlsx"
  const [predictions, setPredictions] = useState([]);
  const [error, setError] = useState("");
  const [max,setMax]=useState(0);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setPredictions([]);

    const formData = new FormData();
    if (inputType === "text") {
      if (!hexData.trim()) {
        setError("Please enter at least one hexadecimal string.");
        return;
      }
      formData.append("hexa", hexData);
    } else if (inputType === "file" && file) {
      formData.append("file", file);
      formData.append("file_type", fileType);
    } else {
      setError("Please provide valid input.");
      return;
    }

    try {
      const response = await axios.post(
        "http://127.0.0.1:5003/predict",
        formData,
        {
          headers: { "Content-Type": "multipart/form-data" },
        }
      );

      if (response.data) {
        ;
        setPredictions(response.data.predictions);
        setHexData("");
      } else {
        setError("Unexpected response format from server.");
        setHexData("");
      }
    } catch (err) {
      console.error(err);
      setError("Wrong Input Format. Please enter a hexadecimal string.");
      setHexData("");
    }
  };
  type result = {
    original: string;
    error?: string; // optional property
    prediction: string[];
    probabilities: number[];
    class_labels: string[];
    sorted_probabilities: number[];
  };
  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 0.8) return "bg-green-200 text-green-800";
    if (confidence >= 0.5) return "bg-yellow-200 text-yellow-800";
    return "bg-red-200 text-red-800";
  };
  return (
<div className="flex flex-col justify-center">
    <div className="container mx-10 relative left-20 w-[70vw] top-10 p-6 bg-white rounded-lg shadow-lg border-x-yellow-800">
    <h1 className="text-2xl font-semibold text-center text-gray-800">Instructions</h1>
    <p className="mt-6 text-gray-700 text-lg">
      There are <strong>2 modes</strong> of input:
    </p>
    <ol className="mt-4 list-decimal pl-6 space-y-4">
      <li>
        <strong>Enter Ciphertext in Hexadecimal Format:</strong>
        <p className="mt-2 text-gray-700">
          Enter your ciphertext in <strong>hexadecimal format</strong>, separated by commas. Ensure that the length of each cipher is even. For example:
          <code className="bg-gray-100 p-1 rounded">ab12, cd34, ef56</code>
        </p>
      </li>
      <li>
        <strong>Upload a File:</strong>
        <p className="mt-2 text-gray-700">
          Choose the relevant file type from the options below and upload a file from your local directory. 
          <strong>For Excel (.xlsx) and CSV (.csv) files:</strong> Ensure that the hex ciphers are placed in the <strong>first column only</strong>, and the first cell is <strong>empty</strong>.
          <br />
          <strong>For Text (.txt) files:</strong> Upload a comma-separated text file with hexadecimal ciphers.
        </p>
      </li>
    </ol>

    <div className="mt-6 text-gray-700  text-lg">
      <strong>Important Notes:</strong>
      <ul className="list-disc pl-6 space-y-2">
        <li>
          Ensure all ciphers are in <strong>hexadecimal format</strong> and have <strong>even length</strong>, only then an output will be generated.
        </li>
        <li>
          Please be patient as both input methods involve heavy computational load, often leading to unwanted errors.
        </li>
      </ul>
    </div>

    <p className="mt-6 text-center text-gray-700">
      Enjoy predicting!
    </p>
  </div>
    
    <div className="container mx-10  bg-white mt-20 mb-20 text-black p-4">
      {/* <h1 className="text-2xl font-bold">Hexadecimal Prediction</h1> */}
       <div className="card-image mt-10 mb-6">
          <img src="./8618881.png" className="h-[5rem]" alt="Logo" />
        </div>

        <div className="card-text">
          <h1 className="text-xl md:text-2xl font-bold leading-tight text-gray-900">
            CryptCrack
          </h1>
          <p className="text-base md:text-lg text-gray-700 mt-3">
            Revolutionizing Encryption Analysis with Cutting-Edge Deep Learning and Machine Learning — Unveiling Hidden Patterns in Nodes, Edges, and Algorithms.
          </p>
        </div>
      <form onSubmit={handleSubmit} className="mt-4">
        <div className="mb-4">
          <label className="mr-4">
            <input
              type="radio"
              value="text"
              checked={inputType === "text"}
              onChange={() => setInputType("text")}
            />
            Text Input
          </label>
          <label className="ml-4">
            <input
              type="radio"
              value="file"
              checked={inputType === "file"}
              onChange={() => setInputType("file")}
            />
            File Upload
          </label>
        </div>

        {inputType === "text" && (
          <textarea
            className="w-full border rounded-md p-2"
            placeholder="Enter hexadecimal strings separated by commas"
            value={hexData}
            onChange={(e) => setHexData(e.target.value)}
            rows={4}
          />
        )}

        {inputType === "file" && (
          <div className="mb-4">
            <input
              type="file"
              accept=".txt,.csv,.xlsx"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
            />
            <select
              value={fileType}
              onChange={(e) => setFileType(e.target.value)}
              className="ml-2 border rounded-md p-2"
            >
              <option value="text">Text File</option>
              <option value="csv">CSV</option>
              <option value="xlsx">XLSX</option>
            </select>
          </div>
        )}

        <button
          type="submit"
          className="bg-blue-500 text-white font-bold px-4 py-2 rounded"
        >
          Predict
        </button>
      </form>


          
      {error && <p className="text-red-500 mt-4">{error}</p>}

      {/* {predictions.length > 0 &&
        predictions.map((result : any, index) => (
          
          <div
            key={index}
            className="mt-6 p-4 border rounded bg-gray-100 space-y-2"
          >
            <h2 className="text-lg font-semibold">Hex: {result.original}</h2>
            {result.error ? (
              <p className="text-red-500 bg-red-100 p-2 rounded">
                Error: {result.error}
              </p>
            ) : (
              <>
                <p className="font-semibold">Top Predictions:</p>
                <ul className="list-disc pl-6">
                  {result.prediction.map((cls : any, idx :number) => (
                    <li key={idx}>
                      {cls}: {result.probabilities[idx].toFixed(2)}
                    </li>
                  ))}
                </ul>

                <Bar
                  data={{
                    labels: result.class_labels,
                    datasets: [
                      {
                        label: "Prediction Probabilities",
                        data: result.sorted_probabilities,
                        backgroundColor: "rgba(75, 192, 192, 0.6)",
                        borderColor: "rgba(75, 192, 192, 1)",
                        borderWidth: 1,
                      },
                    ],
                  }}
                  options={{
                    responsive: true,
                    plugins: {
                      legend: { display: false },
                    },
                    scales: {
                      x: { title: { display: true, text: "Classes" } },
                      y: { title: { display: true, text: "Confidence" } },
                    },
                  }}
                />
              </>
            )}
          </div>
        
          
        ))} */}
        
                {predictions.length > 0 &&
          predictions.map((result: any, index) => {
            const highestConfidence = Math.max(...result.probabilities);
            const highestClass =
              result.prediction[result.probabilities.indexOf(highestConfidence)];
            return (
              <div
                key={index}
                className="mt-6 p-4 border rounded bg-gray-100 space-y-2"
              >
                <h2
  className="text-lg font-semibold break-words"
  style={{ wordBreak: "break-word" }}
>
  Hex: {result.original}
</h2>
                {result.error ? (
                  <p className="text-red-500 bg-red-100 p-2 rounded">
                    Error: {result.error}
                  </p>
                ) : (
                  <>
                    <p className="font-semibold">Top Predictions:</p>
                    <ul className="list-disc pl-6">
                      {result.prediction.map((cls: string, idx: number) => (
                        <li key={idx}>
                          {cls}: {result.probabilities[idx].toFixed(2)}
                        </li>
                      ))}
                    </ul>
                    <p
                      className={`mt-2 p-2 rounded ${getConfidenceColor(
                        highestConfidence
                      )}`}
                    >
                      <strong>Confidence:</strong> {highestClass} -{" "}
                      {(highestConfidence * 100).toFixed(2)}%
                    </p>
                    <Bar
                      data={{
                        labels: result.class_labels,
                        datasets: [
                          {
                            label: "Prediction Probabilities",
                            data: result.sorted_probabilities,
                            backgroundColor: "rgba(75, 192, 192, 0.6)",
                            borderColor: "rgba(75, 192, 192, 1)",
                            borderWidth: 1,
                          },
                        ],
                      }}
                      options={{
                        responsive: true,
                        plugins: {
                          legend: { display: false },
                        },
                        scales: {
                          x: { title: { display: true, text: "Classes" } },
                          y: { title: { display: true, text: "Confidence" } },
                        },
                      }}
                    />
                  </>
                )}
              </div>
            );
          })}
    </div>
    </div>
  );
}
 