import React, { Component } from 'react';
import './Header.css';
import axios from 'axios'

export default class Header extends Component {
  constructor() {
    super();
    this.state = {
      username: '',
      password: '',
      isAdmin: false,
    };
    this.register = this.register.bind(this);
    this.login = this.login.bind(this);
    this.logout = this.logout.bind(this);
  }

  handleUsernameInput(value) {
    this.setState({ username: value });
  }

  handlePasswordInput(value) {
    this.setState({ password: value });
  }

  toggleAdmin() {
    const { isAdmin } = this.state;
    this.setState({ isAdmin: !isAdmin });
  }

  login() {
    const {username, password} = this.state
   axios.post('/auth/login', {username, password})
    .then(user=> 
    this.props.updateUser(user.data),
    this.setState({
      username: '',
      password: ''
    }))
    .catch(err=>
      alert(err.response.request.response),
       this.setState({
      username: '',
      password: ''
    }))
    
    // axios POST to /auth/login here
  }

  register() {
    const {username, password, isAdmin} = this.state
   const res =  axios.post('/auth/register', {username, password, isAdmin})
   .then( res => this.props.updateUser(res.data),
   this.setState({
     username:'',
     password:'',
     isAdmin: res.data
   }))
    .catch(err => {
      this.setState({ username: '', password: '' })
      alert(err.response.request.response)
  }) 
  
    // axios POST to /auth/register here
  }

  logout() {
    axios.get('/auth/logout')
    .then(()=>
    this.props.updateUser({}))
    .catch(err=>
      console.log(err))
    // axios GET to /auth/logout here
  }

  render() {
    const { username, password } = this.state;
    const { user } = this.props;
    return (
      <div className="Header">
        <div className="title">Dragon's Lair</div>
        {user.username ? (
          <div className="welcomeMessage">
            <h4>{user.username}, welcome to the dragon's lair</h4>
            <button type="submit" onClick={this.logout}>
              Logout
            </button>
          </div>
        ) : (
          <div className="loginContainer">
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={e => this.handleUsernameInput(e.target.value)}
            />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={e => this.handlePasswordInput(e.target.value)}
            />
            <div className="adminCheck">
              <input type="checkbox" id="adminCheckbox" onChange={() => this.toggleAdmin()} /> <span> Admin </span>
            </div>
            <button onClick={this.login}>Log In</button>
            <button onClick={this.register} id="reg">
              Register
            </button>
          </div>
        )}
      </div>
    );
  }
}

