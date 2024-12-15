import React from 'react';
import Form from './form';

const Page = () => {
  return (
    <div
      className="bg-cover bg-center bg-repeat min-h-screen"
      style={{ backgroundImage: `url('/20f8fbc5167d7d946d0221a2997cd6e2.jpg')` }}
    >
      <div className="bg-black bg-opacity-50 h-full min-h-screen flex items-center justify-center">
        <Form />
      </div>
    </div>
  );
};

export default Page;
