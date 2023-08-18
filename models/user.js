/** User class for message.ly */
const db = require('../db')
const ExpressError = require('expressError')
const bcrypt = require('bcrypt')
const {BCRYPT_WORK_FACTOR} = require('../config')


/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) {
    let cryptPassword = await bcrypt.hash(password,BCRYPT_WORK_FACTOR)
    const result = await db.query(
      `INSERT INTO users(username, password, first_name, last_name, phone, join_at, last_login_at)
        VALUES($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
        RETURNING username, password, first_name, last_name, phone`, 
      [username, cryptPassword, first_name, last_name, phone]
    )
    return result.rows[0]
   }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const result = await db.query(
      `SELECT password FROM users WHERE username=$1`, [username]
    )
    let user = result.rows[0]
    return user && await bcrypt.compare(user.password, password)
   }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const result = await db.query(
      `UPDATE users 
        SET last_login_at = current_timestamp 
        WHERE username=$1
        RETURNING username`, [username]
    )
    if(!result.rows[0]){
      throw new ExpressError(`Error: username ${username} does not exist`, 404)
    }
   }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const result = await db.query(
      `SELECT username, first_name, last_name, phone FROM users`
    )
    return result.rows;
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
    const result = await db.query(
      `SELECT username, first_name, last_name, phone, join_at, last_login_at 
        FROM users WHERE username=$1`, [username]
    )
    if(!result.rows[0]){
      throw new ExpressError(`Error: username ${username} does not exist`, 404)
    }else{
      return result.rows[0];
    }
   }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) { 
    const result = await db.query(
      `SELECT messages.id, messages.to_username, users.first_name, users.last_name, users.phone, messages.body, messages.sent_at, messages.read_at
        FROM messages JOIN users ON messages.to_username = users.username
        WHERE from_username=$1`, [username]
    )
    const messages = result.rows.map(msg => ({
      id : msg.id,
      to_user : {
        username : msg.to_username,
        first_name : msg.first_name,
        last_name : msg.last_name,
        phone : msg.phone
      },
      body : msg.body,
      sent_at : msg.sent_at,
      read_at : msg.read_at
    }))
    return messages
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const result = await db.query(
      `SELECT messages.id, messages.from_username, users.first_name, users.last_name, users.phone, messages.body, messages.sent_at, messages.read_at
        FROM messages JOIN users ON messages.from_username = users.username
        WHERE to_username=$1`, [username]
    )
    const messages = result.rows.map(msg => ({
      id : msg.id,
      from_user : {
        username : msg.from_username,
        first_name : msg.first_name,
        last_name : msg.last_name,
        phone : msg.phone
      },
      body : msg.body,
      sent_at : msg.sent_at,
      read_at : msg.read_at
    }))
    return messages
   }
}


module.exports = User;