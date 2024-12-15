import React from 'react';
import { Link } from 'react-router-dom'; // Import Link for internal navigation
import { AnimatedPinDemo } from './card';
import GoogleGeminiEffectDemo from './bg';

const page = () => {
  // Example prop values for three different sets
  const set2 = {
    title: "Predict",
    linkhref: "./model2", // Change to internal route
    modelname: "CryptCrack",
    description: "Decode Cipher Mysteries with Our Graph-Based Machine Learning Model, Harnessing Nodes, Edges, Deep Learning and Decision Trees to Reveal Cryptographic Algorithms!",
    bgimg:"./MIT-liquid-networks-Cover.jpg"
  };

  
  

  return (
    <div className='min-h-screen flex flex-col bg-black'>
      <div className="">
        <GoogleGeminiEffectDemo />
      </div>

      <div className=" flex flex-col sm:flex-row bg-black relative -top-[10vh] ">
        <AnimatedPinDemo
          title={set2.title}
          linkhref={set2.linkhref} // Use Link component for internal navigation
          modelname={set2.modelname}
          description={set2.description}
          bgimg={set2.bgimg}
        />
        
      </div>
    </div>
  );
};

export default page;
