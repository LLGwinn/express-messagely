/** User class for message.ly */

const db = require('../db');
const { BCRYPT_WORK_FACTOR } = require("../config");
const ExpressError = require("../expressError");
const bcrypt = require("bcrypt");


/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) { 
    const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    const result = await db.query(
      `INSERT INTO users (username, password, first_name, last_name, phone, join_at)
       VALUES ($1, $2, $3, $4, $5, current_timestamp)
       RETURNING username, password, first_name, last_name, phone`,
       [username, hashedPassword, first_name, last_name, phone]
    );
    return result.rows[0];
  }
  
  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) { 
    const result = await db.query(`SELECT password FROM users WHERE username=$1`, [username]);
    const user = result.rows[0];

    if (!user) { throw new ExpressError(`Username "${username}" not found`, 400) }

    return await bcrypt.compare(password, user.password);
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) { 
    const result = await db.query(`UPDATE users
                                   SET last_login_at=current_timestamp
                                   WHERE username=$1
                                   RETURNING username`,
                                   [username]
                                  );

    if (result.rows.length === 0) { throw new ExpressError(`Username "${username}" not found`, 400) }
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() { 
    const results = await db.query(`SELECT username, first_name, last_name, phone FROM users`);

    return results.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const results = await db.query(
      `SELECT username, first_name, last_name, phone, join_at, last_login_at
       FROM users
       WHERE username=$1`,
       [username]
    );

    if (results.rows.length === 0) {
      throw new ExpressError(`Username "${username}" not found`, 404);
    }

    return results.rows[0];
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) { 
    const results = await db.query(
      `SELECT *
       FROM messages m
       JOIN users AS f ON m.from_username = f.username
       JOIN users AS t ON m.to_username = t.username
       WHERE from_username=$1`,
       [username]
    );
    const messages = results.rows;

    return messages.map(m => {
      let to_user = {username:m.to_username, first_name:m.first_name, last_name:m.last_name, phone:m.phone};
      let { id, body, sent_at, read_at } = m;
      return  {id , body, sent_at, read_at, to_user}
    })
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) { 
    const results = await db.query(
      `SELECT *
       FROM messages m
       JOIN users AS t ON m.to_username = t.username
       JOIN users AS f ON m.from_username = f.username
       WHERE to_username=$1`,
       [username]
    );
    const messages = results.rows;

    return messages.map(m => {
      let from_user = {username:m.from_username, first_name:m.first_name, last_name:m.last_name, phone:m.phone};
      let { id, body, sent_at, read_at } = m;
      return  {id , body, sent_at, read_at, from_user}
    })
  }
}


module.exports = User;