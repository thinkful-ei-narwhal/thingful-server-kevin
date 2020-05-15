const bcrypt = require('bcryptjs');

function requireBasicAuth(req, res, next) {
  const authValue = req.get('Authorization') || '';

  if (!authValue.toLowerCase().startsWith('basic ')) {
    return res.status(401).json({ error: 'Missing basic auth' });
  }

  const token = authValue.split(' ')[1];

  const [ tokenUsername, tokenPassword ] = Buffer
    .from(token, 'base64')
    .toString('ascii')
    .split(':');

  req.app.get('db')('thingful_users')
    .select('*')
    .where({ user_name: tokenUsername })
    .first()
    .then(user => {
      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      return bcrypt.compare(tokenPassword, user.password)
        .then(passwordMatch => {
          if (!passwordMatch) {
            return res.status(401).json({ error: 'Unauthorized request' });
          }
          req.user = user;
          next();
        });
    })
    .catch(next);
}

module.exports = requireBasicAuth;