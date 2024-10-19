import { useState, useEffect } from 'react';
import axios from 'axios';
import { FaEnvelope, FaPhoneAlt, FaCheckCircle, FaSpinner } from 'react-icons/fa';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
const Verification = () => {
  const navigate = useNavigate(); // useNavigate for redirection
  const [loading, setLoading] = useState(false); // Loading state
  const [mobileloading, setmbloading] = useState(false)
  const [email, setEmail] = useState('');
  const [mobile, setMobile] = useState('');
  const [emailOTP, setEmailOTP] = useState('');
  const [mobileOTP, setMobileOTP] = useState('');
  const [isEmailOTPVisible, setIsEmailOTPVisible] = useState(false);
  const [isMobileOTPVisible, setIsMobileOTPVisible] = useState(false);
  const [emailVerified, setEmailVerified] = useState(false);
  const [mobileVerified, setMobileVerified] = useState(false);
  const [message, setMessage] = useState('');

  const token = localStorage.getItem('token');

  // Check verification status on component mount
  const checkVerificationStatus = async () => {
    try {
      const response = await axios.get('http://localhost:8000/api/auth/self', {
        headers: {
          Authorization: `Bearer ${token}`, // Attach token here
        },
      });

      if (response.data.success) {
        const { verified, mobileVerified, name, companyName } = response.data.user;
        if (verified || mobileVerified) {
          navigate('/home', { state: { verified, mobileVerified, name, companyName } });
        }
      }
    } catch (error) {
      console.error('Error fetching verification status:', error);
    }
  };
  useEffect(() => {


    checkVerificationStatus();
  }, [navigate, token, mobileVerified, emailVerified, loading, mobileloading]);

  // Send OTP for email
  const handleSendEmailOTP = async () => {
    setLoading(true)
    try {
      const response = await axios.post('http://localhost:8000/api/auth/send-verification-code', {
        email
      }, {
        headers: {
          Authorization: `Bearer ${token}`, // Attach token here
        },
      });

      if (response.data.success) {
        setMessage('Email verification code sent!');
        toast.success('Email verification code sent!')
        setIsEmailOTPVisible(true); // Show the OTP input
        setLoading(false)
      }
    } catch (error) {
      console.error(error);
      setLoading(false)
      setMessage('Error sending verification code to email.');
    }
  };

  // Verify email OTP
  const handleVerifyEmailOTP = async () => {
    setLoading(true)
    try {
      const response = await axios.post('http://localhost:8000/api/auth/verify-verification-code', {
        email,
        providedCode: emailOTP,
      }, {
        headers: {
          Authorization: `Bearer ${token}`, // Attach token here
        },
      });

      if (response.data.success) {
        setEmailVerified(true);
        setLoading(false)
        setMessage('Email verified successfully!');
        toast.success("Verification Completed")
        checkVerificationStatus();
      }
    } catch (error) {
      setLoading(false)
      console.error(error);
      setMessage('Error verifying email code.');
    }
  };

  // Send OTP for mobile
  const handleSendMobileOTP = async () => {
    setmbloading(true)

    try {


      const response = await axios.post('http://localhost:8000/api/auth/send-verification-code-mobile', {
        phone: '+91' + mobile,
      }, {
        headers: {
          Authorization: `Bearer ${token}`, // Attach token here
        },
      });

      if (response.data.success) {
        setMessage('Mobile verification code sent!');
        toast.success('Mobile verification code sent!')
        setIsMobileOTPVisible(true); // Show the OTP input
        setmbloading(false)
      } else {
        toast.error(response.data.message)
      }

    } catch (error) {
      setmbloading(false)
      console.error(error);

      setMessage('Error sending verification code to mobile.');
    }
  };

  // Verify mobile OTP
  const handleVerifyMobileOTP = async () => {
    setmbloading(true)
    try {
      const response = await axios.post('http://localhost:8000/api/auth/verify-verification-code-mobile', {
        phone: '+91' + mobile,
        otp: mobileOTP,
      }, {
        headers: {
          Authorization: `Bearer ${token}`, // Attach token here
        },
      });

      if (response.data.success) {
        setMobileVerified(true);
        setMessage('Mobile verified successfully!');
        toast.success("Verification Completed")
        setmbloading(false)
        checkVerificationStatus();
      }
    } catch (error) {
      console.error(error);
      setmbloading(false)
      setMessage('Error verifying mobile code.');
    }
  };

  return (
    <div className="flex flex-col h-screen">
      {/* Top Nav */}
      <nav className="flex justify-between items-center p-4 bg-gray-800 text-white">
        <h1 className="text-3xl font-bold">Cuvette</h1>
        <a href="mailto:support@Cuvette.com" className="text-sm font-medium">Contact</a>
      </nav>

      {/* Main Content */}
      <div className="flex flex-grow">
        <div className="w-2/4 bg-gray-100"></div>

        {/* Right side - Form */}
        <div className="w-2/4 flex flex-col justify-center items-center p-8 bg-white">
          <h2 className="text-2xl font-semibold mb-6">Verify Your Account</h2>
          <div className="space-y-4 w-full max-w-md">
            {/* Email Verification */}
            <div className="relative">
              {!isEmailOTPVisible ? (
                <>

                  <FaEnvelope className="absolute left-3 top-3 text-gray-400" />
                  <input
                    type="email"
                    placeholder="Email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="pl-10 p-2 w-full border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    required
                  />
                  <button
                    type="submit"
                    className="w-full p-2 mt-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 flex justify-center items-center"
                    disabled={loading} // Disable button while loading
                    onClick={handleSendEmailOTP}
                  >
                    {loading ? (
                      <FaSpinner className="animate-spin mr-2" /> // Spinner icon, can be replaced with any other spinner component
                    ) : (
                      ' Send Email OTP'
                    )}
                  </button>

                </>
              ) : (
                <>

                  <div className="relative">

                    <input
                      type="text"
                      placeholder="Enter Email OTP"
                      value={emailOTP}
                      onChange={(e) => setEmailOTP(e.target.value)}
                      className=" p-2 w-full border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      required
                    />
                    {emailVerified && <FaCheckCircle className="absolute right-3 top-3 text-green-600" />}
                  </div>

                  <button
                    type="submit"
                    className="w-full mt-2 p-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 flex justify-center items-center"
                    disabled={loading} // Disable button while loading
                    onClick={handleVerifyEmailOTP}
                  >
                    {loading ? (
                      <FaSpinner className="animate-spin mr-2" /> // Spinner icon, can be replaced with any other spinner component
                    ) : (
                      '  Verify Email OTP'
                    )}
                  </button>

                </>
              )}

            </div>

            {/* Mobile Verification */}
            <div className="relative">
              {!isMobileOTPVisible ? (<>
                <FaPhoneAlt className="absolute left-3 top-3 text-gray-400" />
                <input
                  type="tel"
                  placeholder="Mobile"
                  value={mobile}
                  onChange={(e) => setMobile(e.target.value)}
                  className="pl-10  p-2 w-full border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  required
                />

                <button
                  type="submit"
                  className="w-full mt-2 p-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 flex justify-center items-center"
                  disabled={loading} // Disable button while loading
                  onClick={handleSendMobileOTP}
                >
                  {mobileloading ? (
                    <FaSpinner className="animate-spin mr-2" /> // Spinner icon, can be replaced with any other spinner component
                  ) : (
                    '   Send Mobile OTP'
                  )}
                </button>

              </>
              ) : (
                <>

                  <div className="relative">

                    <input
                      type="text"
                      placeholder="Enter Mobile OTP"
                      value={mobileOTP}
                      onChange={(e) => setMobileOTP(e.target.value)}
                      className="p-2  w-full border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      required
                    />
                    {mobileVerified && <FaCheckCircle className="absolute right-3 top-3 text-green-600" />}
                  </div>
                  <button
                    type="submit"
                    className="w-full  mt-2 p-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 flex justify-center items-center"
                    disabled={loading} // Disable button while loading
                    onClick={handleVerifyMobileOTP}
                  >
                    {mobileloading ? (
                      <FaSpinner className="animate-spin mr-2" /> // Spinner icon, can be replaced with any other spinner component
                    ) : (
                      ' Verify Mobile OTP'
                    )}
                  </button>

                </>
              )}

            </div>
          </div>
          {message && <p className="mt-4 text-blue-600">{message}</p>}
        </div>
      </div>
    </div>
  );
};

export default Verification;
