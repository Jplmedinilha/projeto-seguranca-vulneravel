const mysql = require('mysql');
const express = require('express');
const path = require('path');
const crypto = require('crypto');
var jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const fs = require('fs');
require('dotenv').config()

const app = express();
const PORT = 3001;
const secretKey = process.env.JWT_KEY;

const tokensInvalidos = [];

const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: 'jplm12345',
  database: 'security_app_vuln'
};
 
const connection = mysql.createConnection(dbConfig);
  
app.use(express.json());

// ################### CLIENT ####################

app.use(express.static(path.join(__dirname, 'client')));

// app.use((req, res) => {
//   res.sendFile(path.join(__dirname, 'client', 'login.html'));
// });

app.get('/login', async (req, res) => {
  
    res.sendFile(path.join(__dirname, 'client', 'login.html'));

});

app.get('/logout', removeCookie, (req, res) => {
  
  res.redirect('/login');
});

app.get('/public', (req, res) => {

  const searchTerm = req.query.termo || '';

  // Lê o conteúdo do arquivo HTML
  fs.readFile(path.join(__dirname, 'client', 'public.html'), 'utf8', (err, data) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Erro interno no servidor.');
    }

    const replacedHTML = data.replace(/{{#SEARCH_TERM#}}/g, searchTerm);

    res.send(replacedHTML);
  });
});

app.get('/aluno', (req, res) => {
  
    res.sendFile(path.join(__dirname, 'client', 'aluno.html'));

});

app.get('/professor', (req, res) => {
  
    res.sendFile(path.join(__dirname, 'client', 'professor.html'));

});

// ################# SERVER ###################

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    const query = `SELECT 
                    name,
                    username,
                    cargo
                      FROM security_app_vuln.users
                          WHERE username = '${username}' AND password = '${password}'; `;

    connection.query(query, (err, results) => {
      if (err) {
        console.error('Erro ao executar a consulta:', err);
        return;
      }  
      

      if(results.length == 0){
        res.status(200).json({
            FLAG: 'E',
            RETURN: 'Usuário ou senha incorretos'
        })
      } else {
        res.status(200).json({
            FLAG: 'S',
            RETURN: {
              name: results[0].name,
              username: results[0].username,
              tela: "/" + results[0].cargo
            }
        })
      }
      
    });
  });

app.get('/api/getPublic', (req, res) => {

  const searchTerm = req.query.termo || '';

    let query = `SELECT * FROM security_app.cursos `;
    if(searchTerm){
      query += `WHERE UPPER(name) LIKE '%${searchTerm.toUpperCase()}%'; `
    }

    connection.query(query, (err, results) => {
      if (err) {
        res.status(200).json({
          FLAG: 'E',
          RETURN: 'Erro ao executar a consulta:' + err
      })
        return;
      }        

      if(results.length == 0){
        res.status(200).json({
            FLAG: 'E',
            RETURN: 'Nenhum resultado'
        })
      } else {
        res.status(200).json({
            FLAG: 'S',
            RETURN: results
        })
      }
      
    });
  });

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });

// #################### FUNCTIONS ###################

function verificarTokenCookie(req, res, next) {
  
  cookieParser()(req, res, () => {
    const token = req.cookies.token;

    if (tokensInvalidos.includes(token)) {
      return res.redirect('/login');
    }

    // console.log(token)

    if (!token) {
      return res.redirect('/login');
    }

    jwt.verify(token, secretKey, (err, decoded) => {
      if (err) {
        return res.redirect('/login');
      }
      req.user = decoded.user;
      next();
    });
  });
}

function removeCookie(req, res, next) {
  
  cookieParser()(req, res, () => {
    const token = req.cookies.token;

    tokensInvalidos.push(token);

    next();
  });
}

function hashStringWithSHA256(input) {
    const hash = crypto.createHash('sha256');
    hash.update(input);
    return hash.digest('hex');
}

// const generateSecretKey = () => {
//   return crypto.randomBytes(32).toString('hex');
// };

// console.log(generateSecretKey());