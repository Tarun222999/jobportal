import { useState, useEffect } from 'react';
import { FaEnvelope, FaLock, FaUser, FaBuilding, FaPhoneAlt, FaUsers } from 'react-icons/fa';
import { useNavigate, Link } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'react-toastify';

const SignIn = () => {

  const [name, setName] = useState('');
  const [companyName, setCompanyName] = useState('');
  const [companySize, setCompanySize] = useState('');
  const [phone, setPhone] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const token = localStorage.getItem('token');

  // Check verification status on component mount
  useEffect(() => {
    const checkVerificationStatus = async () => {
      try {
        if (!token) return


        const response = await axios.get('https://jobportal-production-2c8f.up.railway.app/api/auth/self', {
          headers: {
            Authorization: `Bearer ${token}`, // Attach token here
          },
        });

        if (response.data.success) {
          const { verified, mobileVerified, name: Name, companyName: cName } = response.data.user;
          if (verified || mobileVerified) {

            navigate('/home', { state: { verified, mobileVerified, name: Name, companyName: cName } });
          } else {
            navigate('/verify')
          }
        }
      } catch (error) {
        console.error('Error fetching verification status:', error);
      }
    };

    checkVerificationStatus();
  }, [navigate, token]);

  const handleRegister = async (e) => {
    e.preventDefault();

    try {
      setPhone((phone) => '+91' + phone)
      const response = await axios.post('https://jobportal-production-2c8f.up.railway.app/api/auth/signup', {
        name,
        companyName,
        companySize,
        phone,
        email,
        password
      });

      if (response.data.success) {
        // Show success toast
        toast.success('Registration successful! Please Login...');
        // Redirect user to SignIn after a short delay
        setTimeout(() => {
          navigate('/signin');
        }, 2000); // Adjust the delay as needed
      } else {
        console.log("at errro")
        toast.error('Registration failed, please try again.');
      }
    } catch (err) {
      console.error(err);
      setError('An error occurred during registration. Please try again.');
    }
  };

  return (
    <div className="flex flex-col h-screen">
      {/* Top Nav */}
      <nav className="flex justify-between items-center p-4 mr-10 text-black">
        <h1 className="text-3xl font-bold">Cuvette</h1>
        <a href="mailto:support@Cuvette.com" className="text-xl font-medium">Contact</a>
      </nav>

      {/* Main Content */}
      <div className="flex flex-grow">
        {/* Left side is empty, can add visuals or keep blank */}
        <div className="w-2/4 bg-gray-100"></div>
        {/* Right side - Form */}
        <div className="w-2/4 flex flex-col justify-center items-center p-8 bg-white">
          <h2 className="text-2xl font-semibold mb-6">Sign In</h2>


          <form onSubmit={handleRegister} className="space-y-4 w-full max-w-md">
            <div className="relative">
              <FaUser className="absolute left-3 top-3 text-gray-400" />
              <input
                type="text"
                placeholder="Name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="pl-10 p-2 w-full border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                required
              />
            </div>
            <div className="relative">
              <FaBuilding className="absolute left-3 top-3 text-gray-400" />
              <input
                type="text"
                placeholder="Company Name"
                value={companyName}
                onChange={(e) => setCompanyName(e.target.value)}
                className="pl-10 p-2 w-full border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                required
              />
            </div>
            <div className="relative">
              <FaUsers className="absolute left-3 top-3 text-gray-400" />
              <input
                type="number"
                placeholder="Company Size"
                value={companySize}
                onChange={(e) => setCompanySize(e.target.value)}
                className="pl-10 p-2 w-full border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                required
              />
            </div>
            <div className="relative">
              <FaPhoneAlt className="absolute left-3 top-3 text-gray-400" />
              <input
                type="tel"
                placeholder="Phone"
                value={phone}
                onChange={(e) => setPhone(e.target.value)}
                className="pl-10 p-2 w-full border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                required
              />
            </div>
            <div className="relative">
              <FaEnvelope className="absolute left-3 top-3 text-gray-400" />
              <input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="pl-10 p-2 w-full border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                required
              />
            </div>
            <div className="relative">
              <FaLock className="absolute left-3 top-3 text-gray-400" />
              <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="pl-10 p-2 w-full border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                required
              />
            </div>
            {error && <p className="text-red-500">{error}</p>}
            <button className="w-full p-2 bg-blue-600 text-white rounded-md hover:bg-blue-700">
              Register
            </button>
          </form>
          <p className="mt-4">
            Already have an account?{' '}
            <Link to="/signin" className="text-blue-600 hover:underline">
              Sign In
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default SignIn;