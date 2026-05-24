// Simulated AI-generated vulnerable JS
const jwt = require('jsonwebtoken')
const cors = require('cors')

// Bad JWT
const decoded = jwt.decode(token, { algorithms: ['none'] })
const role = localStorage.getItem('role')
const isAdmin = localStorage.getItem('admin')

// Bad CORS
app.use(cors())

// XSS
function render() {
  div.dangerouslySetInnerHTML = {{ __html: userInput }}
}

// Bad webhook
app.post('/webhook/stripe', (req, res) => {
  const event = req.body
  processStripeEvent(event)
})
