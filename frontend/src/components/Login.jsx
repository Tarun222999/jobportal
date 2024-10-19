
import axios from 'axios';
import { useState } from 'react';
import { FaEnvelope, FaLock } from 'react-icons/fa';
import { useNavigate, Link } from 'react-router-dom';
import { toast } from 'react-toastify';

const Login = () => {


  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();

    try {
      const response = await axios.post('http://localhost:8000/api/auth/signin', {
        email,
        password,
      });

      const { success, token, verified, mobileVerified, name, companyName } = response.data;
      console.log(name, companyName, success)
      if (success) {
        // Store the token in localStorage
        localStorage.setItem('token', token);

        // Check if both email and mobile are verified
        if (verified || mobileVerified) {
          // Redirect to home if both are verified
          toast.success('Login successful! ');
          navigate('/home', { state: { name, companyName } });
        } else {
          // Redirect to verification screen if either is not verified
          toast.success('Login successful! Please verify your account ');
          navigate('/verify');
        }
      } else {
        setError('Login failed, please check your credentials.');
      }
    } catch (err) {
      console.error(err);
      setError('An error occurred. Please try again later.');
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
          <h2 className="text-2xl font-semibold mb-6">Login</h2>
          <form onSubmit={handleLogin} className="space-y-4 w-full max-w-md">
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
              Login
            </button>
          </form>
          <p className="mt-4">
            To Register a new  account?{' '}
            <Link to="/signup" className="text-blue-600 hover:underline">
              Sign Up
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;