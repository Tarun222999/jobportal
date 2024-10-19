
import './App.css'
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import SignIn from './components/SignIn';
import Verification from './components/Verification';
import Login from './components/Login';
import Home from './components/Home';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css'; // Import the CSS

function App() {





  return (
    <>

      <Router>
        <ToastContainer />
        <Routes>
          <Route path="/" element={<SignIn />} /> {/* Default route: SignIn */}
          <Route path="/signin" element={<Login />} /> {/* Login page */}
          <Route path="/signup" element={<SignIn />} /> {/* Registration page */}
          <Route path="/home" element={<Home />} /> {/* Home page after login */}
          <Route path='/verify' element={<Verification />} />
        </Routes>
      </Router>

    </>

  )
}

export default App
