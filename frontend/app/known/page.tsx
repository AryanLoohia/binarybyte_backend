import React from 'react'

const page = () => {
  return (
    <div className="bg-black min-h-screen relative top-2">  
      <div className="">
<h1 className="mb-4 pt-10 text-center text-4xl font-extrabold leading-none tracking-tight text-gray-900 md:text-5xl lg:text-6xl dark:text-white">Understanding <mark className="px-2 text-white bg-blue-600 rounded dark:bg-blue-500">Encryption</mark> Algorithms</h1>
<p className="text-lg text-center font-normal text-gray-500 lg:text-xl dark:text-gray-400">Analyzing patterns in encryption algorithms and exploring de-cryption methods can be of great academic significance</p>
</div>

<div className="flex-col:sm flex flex-row justify-center flex-wrap m-4 mt-10 p-4">
<div className="w-[30rem] m-4 p-4 rounded overflow-hidden shadow-lg">
  <img className="w-full" src="./rsa.jpeg" alt="Sunset in the mountains"></img>
  <div className="px-6 py-4">
    <div className="font-bold text-xl text-gray-100 mb-2">RSA</div>
    <p className="text-gray-300 text-base">
    RSA, invented by Ron Rivest, Adi Shamir, and Leonard Adleman in 1977, is a widely used asymmetric encryption algorithm based on the mathematical challenge of factoring large prime numbers. This algorithm employs a pair of keys: a public key for encryption and a private key for decryption. RSA key sizes typically range from 1024 to 4096 bits, with larger keys providing stronger security. The security of RSA hinges on the difficulty of factoring the product of two large prime numbers. RSA is integral to many applications, including digital signatures and certificates (e.g., SSL/TLS), secure email and data encryption, and key exchange in secure communication protocols. Its advantages include providing robust security through asymmetric encryption and being widely supported and trusted for secure data transmission. However, RSA is computationally intensive, especially with large keys, and is slower compared to symmetric algorithms like AES. Despite these limitations, RSA remains a cornerstone of modern cryptographic systems, ensuring secure communication and authentication
    </p>
  </div>
  <div className="px-6 pt-4 pb-2">
    <span className="inline-block bg-gray-200 rounded-full px-3 py-1 text-sm font-semibold text-gray-700 mr-2 mb-2">Asymmetric</span>
    <span className="inline-block bg-gray-200 rounded-full px-3 py-1 text-sm font-semibold text-gray-700 mr-2 mb-2">Public Key</span>
    <span className="inline-block bg-gray-200 rounded-full px-3 py-1 text-sm font-semibold text-gray-700 mr-2 mb-2">Data Privacy</span>

  </div>
</div>

<div className="w-[30rem] m-4 p-4 rounded overflow-hidden shadow-lg">
  <img className="w-full" src="./ECC.jpg" alt="Sunset in the mountains"></img>
  <div className="px-6 py-4">
    <div className="font-bold text-xl text-gray-100 mb-2">ECC</div>
    <p className="text-gray-300 text-base">
    Elliptic Curve Cryptography (ECC) is a public-key cryptography method that relies on the algebraic structure of elliptic curves over finite fields, providing strong security with significantly smaller key sizes compared to traditional algorithms like RSA. ECC uses elliptic curves defined by equations to generate public and private key pairs, offering equivalent security to RSA but with much smaller keys (for instance, a 256-bit ECC key provides the same security as a 3072-bit RSA key). This method is highly efficient in terms of computational resources and bandwidth, making it ideal for secure communication protocols like TLS/SSL, digital signatures such as ECDSA, and key exchange mechanisms like ECDH. The advantages of ECC include strong security with shorter key sizes, resulting in faster and more efficient performance. This makes it especially suitable for resource-constrained environments such as mobile devices and Internet of Things (IoT) applications. However, ECC involves more complex mathematical operations compared to RSA and requires careful selection of curves and parameters to avoid vulnerabilities. Despite these challenges, ECC is increasingly favored in modern cryptography due to its efficiency, security, and scalability.
    </p>
  </div>
  <div className="px-6 pt-4 pb-2">
    <span className="inline-block bg-gray-200 rounded-full px-3 py-1 text-sm font-semibold text-gray-700 mr-2 mb-2">Asymmetric</span>
    <span className="inline-block bg-gray-200 rounded-full px-3 py-1 text-sm font-semibold text-gray-700 mr-2 mb-2">Public Key</span><span className="inline-block bg-gray-200 rounded-full px-3 py-1 text-sm font-semibold text-gray-700 mr-2 mb-2">Ellpitic Key</span>
    <span className="inline-block bg-gray-200 rounded-full px-3 py-1 text-sm font-semibold text-gray-700 mr-2 mb-2">Data Privacy</span>
    
  </div>
</div>

<div className="w-[30rem] m-4 p-4 rounded overflow-hidden shadow-lg">
  <img className="w-full" src="./SHA3.jpg" alt="Sunset in the mountains"></img>
  <div className="px-6 py-4">
    <div className="font-bold text-xl text-gray-100 mb-2">SHA</div>
    <p className="text-gray-300 text-base">
    SHA (Secure Hash Algorithm) is a family of cryptographic hash functions designed to ensure data integrity and security. Developed by NIST (National Institute of Standards and Technology), these functions generate fixed-size digests from variable-length input data. The SHA family includes several key variants: SHA-1, which produces a 160-bit hash but is now considered obsolete due to vulnerabilities; SHA-2, which includes SHA-224, SHA-256, SHA-384, and SHA-512, and is secure and widely used; and SHA-3, based on the Keccak algorithm, providing added security. SHA functions are used in various applications, such as data integrity checks (e.g., file verification), digital signatures and certificates, and password hashing and secure storage. The advantages of SHA include resistance to preimage and collision attacks in modern variants, as well as versatility and wide support. SHA remains a cornerstone of modern cryptography, ensuring secure and tamper-proof data verification.
    </p>
  </div>
  <div className="px-6 pt-4 pb-2">
    <span className="inline-block bg-gray-200 rounded-full px-3 py-1 text-sm font-semibold text-gray-700 mr-2 mb-2">Hash</span>
    <span className="inline-block bg-gray-200 rounded-full px-3 py-1 text-sm font-semibold text-gray-700 mr-2 mb-2">Data Integrity</span>
    
  </div>
</div>


<div className="w-[30rem] m-4 p-4 rounded overflow-hidden shadow-lg">
  <img className="w-full" src="./AES.jpg" alt="Sunset in the mountains"></img>
  <div className="px-6 py-4">
    <div className="font-bold text-xl text-gray-100 mb-2">AES</div>
    <p className="text-gray-300 text-base">
    AES (Advanced Encryption Standard) is a secure and widely used symmetric encryption algorithm established by NIST in 2001. It replaced the outdated DES (Data Encryption Standard) due to its vulnerabilities and is renowned for its robustness, efficiency, and versatility. AES operates on 128-bit data blocks and supports key sizes of 128, 192, and 256 bits, with the number of encryption rounds varying based on the key size (10 rounds for 128-bit keys, 12 rounds for 192-bit keys, and 14 rounds for 256-bit keys). It is widely used in secure communication protocols like TLS and VPNs, as well as in applications such as disk encryption and financial data protection. Known for its high level of security, AES is resistant to cryptographic attacks, making it the standard encryption algorithm for ensuring data confidentiality across a wide range of systems.
    </p>
  </div>
  <div className="px-6 pt-4 pb-2">
    <span className="inline-block bg-gray-200 rounded-full px-3 py-1 text-sm font-semibold text-gray-700 mr-2 mb-2">Symmetric</span>
    <span className="inline-block bg-gray-200 rounded-full px-3 py-1 text-sm font-semibold text-gray-700 mr-2 mb-2">Block</span>
    
  </div>
</div>

<div className="w-[30rem]  m-4 p-4 rounded overflow-hidden shadow-lg">
  <img className="w-full" src="./SIH2024_PPT_BinaryByte.png" alt="Sunset in the mountains"></img>
  <div className="px-6 py-4">
    <div className="font-bold text-xl text-gray-100 mb-2">Rabbit</div>
    <p className="text-gray-300 text-base">
    Rabbit is a lightweight symmetric stream cipher designed for high-speed encryption in software environments. Introduced in 2003 as part of the eSTREAM project, Rabbit operates with a 128-bit key and a 64-bit initialization vector (IV). It is known for its high throughput and low memory requirements, using a combination of linear transformations and non-linear operations to ensure security. Rabbit is optimized for software implementation, providing strong encryption with minimal computational overhead, making it ideal for encrypting data in resource-constrained devices and ensuring secure communication in embedded systems. Its efficiency and high-speed encryption capabilities make Rabbit well-suited for environments that demand robust security with limited resources.
    </p>
  </div>
  <div className="px-6 pt-4 pb-2">
    <span className="inline-block bg-gray-200 rounded-full px-3 py-1 text-sm font-semibold text-gray-700 mr-2 mb-2">Stream</span>
    <span className="inline-block bg-gray-200 rounded-full px-3 py-1 text-sm font-semibold text-gray-700 mr-2 mb-2">Initialisation Vector</span>

  </div>
</div>
<div className="w-[30rem]  m-4 p-4 rounded overflow-hidden shadow-lg">
  <img className="w-full" src="./MD5.jpg" alt="Sunset in the mountains"></img>
  <div className="px-6 py-4">
    <div className="font-bold text-xl text-gray-100 mb-2">MD5</div>
    <p className="text-gray-300 text-base">
    MD5, developed by Ron Rivest in 1991, is a widely used cryptographic hash function that produces a 128-bit hash value from input data. This hash value is commonly represented as a 32-character hexadecimal number. Initially designed for integrity checking and digital signatures, MD5 is known for its fast and simple computation. It is often used for file integrity verification, digital signatures, and password hashing in older systems, as well as for storing hash values for data comparison. The advantages of MD5 include its fast and efficient hash computation and its simplicity and widespread support in legacy systems. However, MD5 is vulnerable to collision attacks, where different inputs can produce the same hash value, making it unsuitable for cryptographic use in security-critical applications. Due to these vulnerabilities, MD5 is no longer recommended for secure applications and has largely been replaced by more secure hash functions like SHA-256 in modern applications.
    </p>
  </div>
  <div className="px-6 pt-4 pb-2">
    <span className="inline-block bg-gray-200 rounded-full px-3 py-1 text-sm font-semibold text-gray-700 mr-2 mb-2">Hash</span>
    <span className="inline-block bg-gray-200 rounded-full px-3 py-1 text-sm font-semibold text-gray-700 mr-2 mb-2">Data Integrity</span>

  </div>
</div>

<div className="w-[30rem]  m-4 p-4 rounded overflow-hidden shadow-lg">
  <img className="w-full" src="./ECDSA.jpg" alt="Sunset in the mountains"></img>
  <div className="px-6 py-4">
    <div className="font-bold text-xl text-gray-100 mb-2">ECDSA</div>
    <p className="text-gray-300 text-base">
    ECDSA (Elliptic Curve Digital Signature Algorithm) is a digital signature algorithm based on elliptic curve cryptography (ECC), providing a method for verifying the authenticity and integrity of messages using a public-private key pair. ECDSA uses elliptic curve mathematics to generate shorter, more efficient keys compared to RSA, offering equivalent security with smaller key sizes. It provides digital signatures for message authentication, with signature sizes smaller than those of RSA, enhancing performance in constrained environments. The security of ECDSA is based on the difficulty of the elliptic curve discrete logarithm problem. ECDSA is widely used in digital signatures for protocols like SSL/TLS and Bitcoin, as well as for secure software distribution, authentication, and integrity verification. Due to its efficiency and compact key sizes, it is often implemented in mobile devices and IoT systems. The advantages of ECDSA include strong security with shorter key sizes (e.g., a 256-bit key providing similar security to a 3072-bit RSA key), efficient processing power and storage, and suitability for resource-constrained environments. However, ECDSA involves more complex mathematical operations compared to RSA and requires careful parameter selection to avoid vulnerabilities in weak curves. 
    </p>
  </div>
  <div className="px-6 pt-4 pb-2">
    <span className="inline-block bg-gray-200 rounded-full px-3 py-1 text-sm font-semibold text-gray-700 mr-2 mb-2">Digital Signature</span>
    <span className="inline-block bg-gray-200 rounded-full px-3 py-1 text-sm font-semibold text-gray-700 mr-2 mb-2">Data Integrity</span>

  </div>
</div>

<div className="w-[30rem]  m-4 p-4 rounded overflow-hidden shadow-lg">
  <img className="w-full" src="./HMAC.jpg" alt="Sunset in the mountains"></img>
  <div className="px-6 py-4">
    <div className="font-bold text-xl text-gray-100 mb-2">HMAC</div>
    <p className="text-gray-300 text-base">
    HMAC (Hash-based Message Authentication Code) is a cryptographic method that combines a hash function with a secret key to verify the integrity and authenticity of a message. By using a hash function like SHA-256 and a secret key, HMAC ensures that a message has not been altered and that it comes from a legitimate source. It is used in various applications such as protocols like TLS, IPSec, and SSH, and for verifying data integrity in APIs and authentication systems. The advantages of HMAC include strong security when combined with a secure hash function, and its efficiency and wide support. However, its security relies on keeping the secret key secure and depends on the strength of the underlying hash function. HMAC is widely used to ensure secure data transmission and message authenticity, making it a fundamental component in many modern cryptographic systems.
    </p>
  </div>
  <div className="px-6 pt-4 pb-2">
    <span className="inline-block bg-gray-200 rounded-full px-3 py-1 text-sm font-semibold text-gray-700 mr-2 mb-2">MAC</span>
    <span className="inline-block bg-gray-200 rounded-full px-3 py-1 text-sm font-semibold text-gray-700 mr-2 mb-2">Data Integrity</span>

  </div>
</div>

<div className="w-[30rem]  m-4 p-4 rounded overflow-hidden shadow-lg">
  <img className="w-full" src="./CHACHA20.jpg" alt="Sunset in the mountains"></img>
  <div className="px-6 py-4">
    <div className="font-bold text-xl text-gray-100 mb-2">ChaCha20</div>
    <p className="text-gray-300 text-base">
    ChaCha20 is a modern symmetric stream cipher designed by Daniel J. Bernstein as a variant of the Salsa family of ciphers. Known for its speed, security, and simplicity, ChaCha20 operates on 512-bit state blocks and uses a 256-bit key along with a 96-bit nonce. It is lightweight and often faster than AES in software implementations, making it resistant to timing attacks. ChaCha20 is widely used in secure communication protocols like TLS and HTTPS, as well as for encrypting data in devices with limited computational power. Its high performance in software environments and strong security against cryptographic attacks have led to its adoption in many modern encryption systems, where its efficiency and robustness are highly valued.
    </p>
  </div>
  <div className="px-6 pt-4 pb-2">
    <span className="inline-block bg-gray-200 rounded-full px-3 py-1 text-sm font-semibold text-gray-700 mr-2 mb-2">Privacy</span>
    <span className="inline-block bg-gray-200 rounded-full px-3 py-1 text-sm font-semibold text-gray-700 mr-2 mb-2">Symmetric Stream</span>

  </div>
</div>
<div className="w-[30rem]  m-4 p-4 rounded overflow-hidden shadow-lg">
  <img className="w-full" src="./3DES.jpg" alt="Sunset in the mountains"></img>
  <div className="px-6 py-4">
    <div className="font-bold text-xl text-gray-100 mb-2">3DES</div>
    <p className="text-gray-300 text-base">
    3DES, or Triple Data Encryption Standard, is a symmetric encryption algorithm that enhances the security of the original DES by applying it three times in an Encrypt-Decrypt-Encrypt (EDE) process. It operates on 64-bit data blocks and uses three 56-bit keys, providing either 112-bit or 168-bit effective security, depending on the key usage. Although 3DES offers stronger security than DES due to the triple encryption process and compatibility with DES systems, it is slower than modern algorithms like AES. 3DES is commonly used in legacy systems in banking and finance, as well as in VPNs and secure communications where AES is not supported. However, it is computationally intensive and vulnerable to certain cryptographic attacks, making it considered outdated. As a result, 3DES is gradually being phased out in favor of stronger and more efficient algorithms like AES.
    </p>
  </div>
  <div className="px-6 pt-4 pb-2">
    <span className="inline-block bg-gray-200 rounded-full px-3 py-1 text-sm font-semibold text-gray-700 mr-2 mb-2">Privacy</span>
    <span className="inline-block bg-gray-200 rounded-full px-3 py-1 text-sm font-semibold text-gray-700 mr-2 mb-2">Symmetric Stream</span>

  </div>
</div>


</div>
    </div>
  )
}

export default page
