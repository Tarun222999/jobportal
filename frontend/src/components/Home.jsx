import { useState } from 'react';
import { FaPlus } from 'react-icons/fa';
import JobModal from './JobModal';
import { useLocation, useNavigate } from 'react-router-dom';
import axios from 'axios';

const Home = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { name, companyName } = location.state || {};
  console.log(name, companyName)
  const [showDropdown, setShowDropdown] = useState(false);
  const [showJobModal, setShowJobModal] = useState(false);

  const openJobModal = () => setShowJobModal(true);
  const closeJobModal = () => setShowJobModal(false);
  const toggleDropdown = () => setShowDropdown(!showDropdown);

  const handleLogout = async () => {
    try {
      const token = localStorage.getItem('token'); // Retrieve token from local storage
      const response = await axios.post('https://jobportal-production-2c8f.up.railway.app/api/auth/signout', {}, {
        headers: {
          Authorization: `Bearer ${token}`, // Attach token in the header
        },
      });

      if (response.data.success) {
        localStorage.removeItem('token'); // Remove token from localStorage
        navigate('/signin'); // Redirect to the login page
      }
    } catch (error) {
      console.error('Logout failed:', error);
      // Optionally, show an error message to the user
    }
  };
  return (
    <div className="flex flex-col h-screen">
      {/* Top Nav */}
      <nav className="flex justify-between items-center p-4 mr-10 text-black">
        <h1 className="text-3xl font-bold">Cuvvete</h1>

        <div className="relative">
          <div className='flex flex-row gap-2'>
            <a href="mailto:support@cuvvete.com" className="text-xl font-medium ml-[50px]">Contact</a>
            <button onClick={toggleDropdown} className="flex items-center">
              <span className="mr-2 text-xl font-semibold">{name}</span>
              <span>&#x25BC;</span> {/* Dropdown arrow */}
            </button>
          </div>

          {showDropdown && (
            <div className="absolute right-0 mt-2 w-48 bg-white border rounded-md shadow-lg mb-2">
              <div className="p-2">
                <p className="font-semibold ml-2">{companyName}</p>
                <button onClick={handleLogout} className="w-full text-left p-2 hover:bg-gray-200">
                  Logout
                </button>
              </div>
            </div>
          )}
        </div>
      </nav>

      {/* Main Content */}
      <div className="flex m-4 ">
        <button
          onClick={openJobModal}
          className="flex  bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700"
        >
          <FaPlus className="mr-2" /> Create Interview
        </button>
      </div>

      {/* Job Modal */}
      {showJobModal && <JobModal onClose={closeJobModal} />}
    </div>
  );
};

export default Home;
