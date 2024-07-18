// After successful login, serve index.js
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], async (err, results) => {
    if (err) {
      return res.status(500).send('Database error');
    }

    if (results.length === 0) {
      return res.status(400).send('User not found');
    }

    const user = results[0];

    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      return res.status(400).send('Invalid password');
    }

    req.session.userId = user.id;
    res.sendFile(path.join(__dirname, 'index.js'));
  });
});

