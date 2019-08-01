import React, { Component } from 'react';
import axios from 'axios';
import './App.css';

class App extends Component {
  constructor(props) {
    super(props);
    this.state = {
      emailInput: '',
      passwordInput: '',
      user: {}
    }
  }

  async signup() {
    let res = await axios.post('/api/signup', {
      email: this.state.emailInput,
      password: this.state.passwordInput
    })
    this.setState({
      user: res.data.userData
    })

  }

  async login() {
    let res = await axios.post('/api/login', {
      email: this.state.emailInput,
      password: this.state.passwordInput
    })
    this.setState({
      user: res.data.userData
    })
  }

  async logout() {
    let res = await axios.get('/logout')
    this.setState({ user: {} })
  }

  render() {
    return (
      <div className="App">
        <h1>Auth Mini</h1>
        <p>
          Email:
          <input onChange={(e) => this.setState({ emailInput: e.target.value })} type="text" />
        </p>
        <p>
          Password:
          <input onChange={(e) => this.setState({ passwordInput: e.target.value })} type="text" />
        </p>
        <button onClick={() => this.signup()}>Signup</button>
        <button onClick={() => this.login()}>Login</button>
        <button onClick={() => this.logout()}>Logout</button>
        <hr />
        <p>USER: {JSON.stringify(this.state.user)}</p>
      </div>
    );
  }
}

export default App;
