import { useState } from 'react';
import { FaTimes, FaSearch, FaSpinner } from 'react-icons/fa';
import axios from 'axios';
import { toast } from 'react-toastify';

// eslint-disable-next-line react/prop-types
const JobModal = ({ onClose }) => {
  const [loading, setLoading] = useState(false); // Loading state
  const [selectedCandidates, setSelectedCandidates] = useState([]);
  const [candidateSearch, setCandidateSearch] = useState('');
  const [jobTitle, setJobTitle] = useState('');
  const [jobDescription, setJobDescription] = useState('');
  const [experienceLevel, setExperienceLevel] = useState('');
  const [endDate, setEndDate] = useState('');
  const token = localStorage.getItem('token');
  const handleCandidateSearch = (e) => {
    setCandidateSearch(e.target.value);
  };

  const handleAddCandidate = () => {
    if (candidateSearch && !selectedCandidates.includes(candidateSearch)) {
      setSelectedCandidates([...selectedCandidates, candidateSearch]);
      setCandidateSearch('');
    }
  };

  const handleRemoveCandidate = (candidate) => {
    setSelectedCandidates(selectedCandidates.filter(c => c !== candidate));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true); // Set loading to true when form submission starts
    try {
      const response = await axios.post('https://jobportal-production-2c8f.up.railway.app/api/posts/create-post', {
        title: jobTitle,
        description: jobDescription,
        expLvl: experienceLevel,
        candidates: selectedCandidates,
        endDate: endDate,
      }, {
        headers: {
          Authorization: `Bearer ${token}`, // Attach token in the header
        }
      });

      if (response.data.success) {
        console.log('Job created successfully:', response.data.data);
        toast.success("Hurray Job Created,Emails Sent")
        // Close the modal after successful submission
        setLoading(false);
        onClose();
      }
    } catch (error) {


      setLoading(false);
      console.error('Error creating job:', error);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex justify-center items-center z-50">
      <div className="bg-white w-full max-w-2xl p-8 rounded-md shadow-lg relative">
        <button onClick={onClose} className="absolute top-4 right-4 text-gray-500 hover:text-gray-700">
          <FaTimes />
        </button>
        <h2 className="text-2xl font-semibold mb-4">Add Job</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700">Job Title</label>
            <input
              type="text"
              placeholder="Job Title"
              value={jobTitle}
              onChange={(e) => setJobTitle(e.target.value)}
              className="w-full p-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Description</label>
            <textarea
              placeholder="Job Description"
              value={jobDescription}
              onChange={(e) => setJobDescription(e.target.value)}
              className="w-full p-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Experience Level</label>
            <select
              value={experienceLevel}
              onChange={(e) => setExperienceLevel(e.target.value)}
              className="w-full p-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">Select Experience Level</option>
              <option value="Junior">Junior</option>
              <option value="Mid">Mid</option>
              <option value="Senior">Senior</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Candidates</label>
            <div className="relative flex items-center">
              <FaSearch className="absolute left-3 top-3 text-gray-400" />
              <input
                type="text"
                value={candidateSearch}
                onChange={handleCandidateSearch}
                placeholder="Search Candidates"
                className="pl-10 p-2 w-full border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <button
                type="button"
                onClick={handleAddCandidate}
                className="ml-2 p-2 bg-blue-600 text-white rounded-md"
              >
                Add
              </button>
            </div>
            <div className="mt-2">
              {selectedCandidates.map((candidate, index) => (
                <span
                  key={index}
                  className="inline-block bg-gray-200 px-2 py-1 text-sm rounded-full mr-2 relative"
                >
                  {candidate}
                  <button
                    type="button"
                    onClick={() => handleRemoveCandidate(candidate)}
                    className="absolute top-0 right-0 text-red-500 text-xs"
                  >
                    x
                  </button>
                </span>
              ))}
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">End Date</label>
            <input
              type="date"
              value={endDate}
              onChange={(e) => setEndDate(e.target.value)}
              className="w-full p-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <button
            type="submit"
            className="w-full p-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 flex justify-center items-center"
            disabled={loading} // Disable button while loading
          >
            {loading ? (
              <FaSpinner className="animate-spin mr-2" /> // Spinner icon, can be replaced with any other spinner component
            ) : (
              'Send'
            )}
          </button>
        </form>
      </div>
    </div>
  );
};

export default JobModal;
