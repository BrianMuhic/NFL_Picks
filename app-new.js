/*
 * NFL Weekly Picks – Clean, organized Node/Express app using SQLite
 * Features:
 * - Username/password auth (bcrypt-hashed)
 * - View all NFL games for a given week
 * - Make picks for winners (one pick per game per user)
 * - Admin endpoints to seed games and set winners
 * - Weekly leaderboard (most correct picks)
 * - Real NFL API integration
 * - Pick deadlines and admin controls
 */

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const csurf = require('csurf');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');

// Import our modules
const { db, uuidv4 } = require('./config/database');
const { requireAuth, requireAdmin, canMakePicks, getPickDeadline, weekSelector, currentWeek } = require('./utils/helpers');
const { tplLayout, tplAuth } = require('./utils/templates');
const { fetchNFLGames, populateFullSeason } = require('./services/nfl-api');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Security & middleware ---
app.use(helmet());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 * 7 },
  })
);
const csrfProtection = csurf({ cookie: true });

// Initialize database and populate with current season games
(async () => {
  // Create tables if they don't exist
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      is_admin BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS games (
      id TEXT PRIMARY KEY,
      week INTEGER NOT NULL,
      away TEXT NOT NULL,
      home TEXT NOT NULL,
      kickoff TEXT,
      nfl_game_id TEXT,
      status TEXT DEFAULT 'scheduled',
      away_score INTEGER,
      home_score INTEGER,
      winner TEXT CHECK(winner IN ('home', 'away')),
      UNIQUE(week, away, home)
    );

    CREATE TABLE IF NOT EXISTS picks (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      game_id TEXT NOT NULL,
      pick TEXT NOT NULL CHECK(pick IN ('home', 'away')),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id),
      FOREIGN KEY(game_id) REFERENCES games(id),
      UNIQUE(user_id, game_id)
    );

    CREATE TABLE IF NOT EXISTS pick_deadlines (
      week INTEGER PRIMARY KEY,
      deadline TEXT NOT NULL
    );
  `);
  
  try {
    await populateFullSeason();
  } catch (error) {
    console.log('Note: Could not populate season games (API might be unavailable):', error.message);
  }
})();

// --- Auth routes ---
app.get('/register', csrfProtection, (req, res) => {
  res.send(tplLayout('Sign up', tplAuth('Create account', 'register', req.csrfToken()), req));
});

app.post('/register', csrfProtection, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).send(tplLayout('Sign up', tplAuth('Create account', 'register', req.csrfToken(), 'Username and password are required.'), req));
  }
  
  try {
    // inside app.post('/register', ...)
    const id = uuidv4();
    const hash = await bcrypt.hash(password, 10);

    // Check if this is the first user (who becomes admin)
    const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
    const isAdmin = userCount === 0;

    // Convert boolean to integer for SQLite binding (0 or 1)
    const stmt = db.prepare('INSERT INTO users (id, username, password_hash, is_admin) VALUES (?, ?, ?, ?)');
    stmt.run(id, username.trim(), hash, isAdmin ? 1 : 0);

    // store a boolean in the session for easier checks later
    req.session.user = { id, username: username.trim(), is_admin: !!isAdmin };

    
    // Redirect to current week
    const week = currentWeek(req);
    res.redirect(`/?week=${week}`);
  } catch (e) {
    console.error('Registration error:', e);
    const msg = e && e.code === 'SQLITE_CONSTRAINT_UNIQUE' ? 'Username already exists.' : 'Failed to create account.';
    res.status(400).send(tplLayout('Sign up', tplAuth('Create account', 'register', req.csrfToken(), msg), req));
  }
});

app.get('/login', csrfProtection, (req, res) => {
  res.send(tplLayout('Log in', tplAuth('Log in', 'login', req.csrfToken()), req));
});

app.post('/login', csrfProtection, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).send(tplLayout('Log in', tplAuth('Log in', 'login', req.csrfToken(), 'Username and password are required.'), req));
  }
  
  try {
    const row = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim());
    if (!row) {
      return res.status(401).send(tplLayout('Log in', tplAuth('Log in', 'login', req.csrfToken(), 'Invalid credentials.'), req));
    }
    
    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) {
      return res.status(401).send(tplLayout('Log in', tplAuth('Log in', 'login', req.csrfToken(), 'Invalid credentials.'), req));
    }
    
    // inside app.post('/login', ...)
    req.session.user = { id: row.id, username: row.username, is_admin: !!row.is_admin };

    
    // Redirect to current week
    const week = currentWeek(req);
    res.redirect(`/?week=${week}`);
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).send(tplLayout('Log in', tplAuth('Log in', 'login', req.csrfToken(), 'Server error. Please try again.'), req));
  }
});

app.post('/logout', csrfProtection, (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// --- Main picks route ---
app.get('/', csrfProtection, requireAuth, (req, res) => {
  const weekParam = req.query.week;
  const week = weekParam ? parseInt(weekParam, 10) : null;
  
  // If no week parameter or invalid week, redirect to current week
  if (!week || isNaN(week) || week < 1 || week > 18) {
    const currentWeekNum = currentWeek(req);
    return res.redirect(`/?week=${currentWeekNum}`);
  }
  
  const games = db.prepare('SELECT * FROM games WHERE week = ? ORDER BY datetime(kickoff) ASC').all(week);
  const picks = db.prepare('SELECT * FROM picks WHERE user_id = ?').all(req.session.user.id);
  const pickMap = new Map(picks.map(p => [p.game_id, p.pick]));
  
  const canMakePicksNow = canMakePicks(week);
  const deadline = getPickDeadline(week);
  const deadlineText = deadline ? new Date(deadline).toLocaleString() : 'No deadline set';

  const body = `
    <div class="card">
      <div class="row" style="justify-content:space-between;align-items:center">
        <h1 style="margin:0">Make Your Picks</h1>
        ${weekSelector(week, 'home')}
      </div>
      ${!canMakePicksNow ? `<div style="background:#F94449;border:1px solid #f59e0b;border-radius:8px;padding:12px;margin-bottom:16px"><strong>⚠️ Picks are closed for Week ${week}</strong><br><span class="muted">Deadline was: ${deadlineText}</span></div>` : ''}
      ${deadline && canMakePicksNow ? `<div style="background:#10b981;border:1px solid #10b981;border-radius:8px;padding:12px;margin-bottom:16px"><strong>⏰ Picks close: ${deadlineText}</strong></div>` : ''}
      ${games.length === 0 ? `<p class="muted">No games yet for this week. Use admin to fetch games from NFL API.</p>` : ''}
      <form method="POST" action="/picks" ${!canMakePicksNow ? 'style="opacity:0.5;pointer-events:none"' : ''}>
        <input type="hidden" name="_csrf" value="${req.csrfToken()}">
        <input type="hidden" name="week" value="${week}">
        <table>
          <thead><tr><th>Matchup</th><th>Kickoff</th><th>Your pick</th><th>Result</th></tr></thead>
          <tbody>
            ${games.map(g => {
              const userPick = pickMap.get(g.id) || '';
              const decided = g.winner === 'home' || g.winner === 'away';
              const result = decided ? (g.winner === userPick ? '✅' : '❌') : '—';
              return `<tr>
                <td>${g.away} @ ${g.home}</td>
                <td class="muted">${g.kickoff ? new Date(g.kickoff).toLocaleString() : ''}</td>
                <td>
                  <label class="row" style="gap:10px">
                    <span class="pill">Away: ${g.away}</span>
                    <input type="radio" name="pick_${g.id}" value="away" ${userPick==='away'?'checked':''} ${!canMakePicksNow ? 'disabled' : ''}>
                    <span class="pill">Home: ${g.home}</span>
                    <input type="radio" name="pick_${g.id}" value="home" ${userPick==='home'?'checked':''} ${!canMakePicksNow ? 'disabled' : ''}>
                  </label>
                </td>
                <td>${result}</td>
              </tr>`;
            }).join('')}
          </tbody>
        </table>
        <div class="row" style="margin-top:12px;justify-content:flex-end">
          <button class="btn btn-primary" ${!canMakePicksNow ? 'disabled' : ''}>Save Picks</button>
        </div>
      </form>
    </div>
  `;
  res.send(tplLayout('Your Picks', body, req));
});

// --- Picks submission ---
app.post('/picks', csrfProtection, requireAuth, (req, res) => {
  const userId = req.session.user.id;
  const week = parseInt(req.body.week, 10) || 1;
  
  // Check if picks are still allowed
  if (!canMakePicks(week)) {
    return res.status(400).send(tplLayout('Picks Closed', `<div class="card"><h1>Picks are closed</h1><p class="muted">The deadline for Week ${week} has passed. You can no longer make or change picks.</p></div>`, req));
  }
  
  const entries = Object.entries(req.body).filter(([k]) => k.startsWith('pick_'));
  const upsert = db.prepare(`INSERT INTO picks (id, user_id, game_id, pick) VALUES (?, ?, ?, ?) ON CONFLICT(user_id, game_id) DO UPDATE SET pick = excluded.pick`);
  const gamesById = new Map(db.prepare('SELECT id FROM games').all().map(g => [g.id, true]));

  const tx = db.transaction(() => {
    for (const [key, value] of entries) {
      const gameId = key.replace('pick_', '');
      if (!gamesById.has(gameId)) continue;
      const pick = value === 'home' ? 'home' : 'away';
      upsert.run(uuidv4(), userId, gameId, pick);
    }
  });
  tx();
  
  res.redirect(`/?week=${week}`);
});

// --- Games list ---
app.get('/games', csrfProtection, (req, res) => {
  const weekParam = req.query.week;
  const week = weekParam ? parseInt(weekParam, 10) : currentWeek(req);
  
  if (isNaN(week) || week < 1 || week > 18) {
    return res.redirect(`/games?week=${currentWeek(req)}`);
  }
  
  const games = db.prepare('SELECT * FROM games WHERE week = ? ORDER BY datetime(kickoff) ASC').all(week);
  const body = `
    <div class="card">
      <div class="row" style="justify-content:space-between;align-items:center">
        <h1 style="margin:0">Games - Week ${week}</h1>
        ${weekSelector(week, 'games')}
      </div>
      <table>
        <thead><tr><th>Matchup</th><th>Kickoff</th><th>Score</th><th>Status</th></tr></thead>
        <tbody>
          ${games.length === 0 ? '<tr><td colspan="4" class="muted">No games scheduled for this week yet.</td></tr>' : ''}
          ${games.map(g => `<tr>
            <td>${g.away} @ ${g.home}</td>
            <td class="muted">${g.kickoff ? new Date(g.kickoff).toLocaleString() : ''}</td>
            <td>${g.away_score !== null && g.home_score !== null ? `${g.away_score} - ${g.home_score}` : '—'}</td>
            <td>${g.winner ? `Winner: <strong>${g.winner === 'home' ? g.home : g.away}</strong>` : g.status}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>
  `;
  res.send(tplLayout('Games', body, req));
});

// --- Leaderboard ---
app.get('/leaderboard', csrfProtection, (req, res) => {
  const weekParam = req.query.week;
  const week = weekParam ? parseInt(weekParam, 10) : currentWeek(req);
  
  if (isNaN(week) || week < 1 || week > 18) {
    return res.redirect(`/leaderboard?week=${currentWeek(req)}`);
  }
  
  // Get current week's scores
  const weeklyScores = db.prepare(`
    SELECT u.username,
           u.id,
           SUM(CASE WHEN g.winner IS NOT NULL AND p.pick = g.winner THEN 1 ELSE 0 END) AS correct,
           COUNT(p.id) AS picks_made
    FROM users u
    LEFT JOIN picks p ON p.user_id = u.id
    LEFT JOIN games g ON g.id = p.game_id AND g.week = ?
    WHERE g.week = ?
    GROUP BY u.id, u.username
    ORDER BY correct DESC, u.username COLLATE NOCASE ASC
  `).all(week, week);

  // Determine weekly winners (handle ties)
  let weeklyWinners = [];
  if (weeklyScores.length > 0) {
    const maxCorrect = Math.max(...weeklyScores.map(s => s.correct));
    weeklyWinners = weeklyScores.filter(s => s.correct === maxCorrect && s.correct > 0);
  }

  // Calculate overall weekly wins for each user
  const overallWins = calculateWeeklyWins();

  const body = `
    <div class="card">
      <div class="row" style="justify-content:space-between;align-items:center">
        <h1 style="margin:0">Leaderboard</h1>
        ${weekSelector(week, 'leaderboard')}
      </div>
      
      <h3>Week ${week} Results</h3>
      <table>
        <thead><tr><th>User</th><th>Correct Picks</th><th>Total Picks</th><th>Week Winner</th></tr></thead>
        <tbody>
          ${weeklyScores.length > 0 ? weeklyScores.map(r => {
            const isWinner = weeklyWinners.some(w => w.id === r.id);
            const winnerIcon = isWinner ? '🏆' : '';
            const rowStyle = isWinner ? 'background-color: #00aeff84; font-weight: bold;' : '';
            return `<tr style="${rowStyle}">
              <td>${r.username}</td>
              <td>${r.correct || 0}</td>
              <td class="muted">${r.picks_made || 0}</td>
              <td>${winnerIcon}</td>
            </tr>`;
          }).join('') : '<tr><td colspan="4" class="muted">No picks made for this week yet.</td></tr>'}
        </tbody>
      </table>
      
      ${weeklyWinners.length > 0 ? `
        <div style="background:#013220;border:1px solid #10b981;border-radius:8px;padding:12px;margin-top:12px">
          <strong>Week ${week} Winner${weeklyWinners.length > 1 ? 's' : ''}:</strong> 
          ${weeklyWinners.map(w => w.username).join(', ')} 
          (${weeklyWinners[0].correct} correct pick${weeklyWinners[0].correct !== 1 ? 's' : ''})
        </div>
      ` : ''}
    </div>

    <div class="card" style="margin-top:16px">
      <h3>Season Standings (Weekly Wins)</h3>
      <table>
        <thead><tr><th>Rank</th><th>User</th><th>Weekly Wins</th><th>Total Correct Picks</th></tr></thead>
        <tbody>
          ${overallWins.length > 0 ? overallWins.map((r, index) => {
            let rank = index + 1;
            // Handle ties in ranking
            if (index > 0 && overallWins[index - 1].weekly_wins === r.weekly_wins) {
              // Find the rank of the previous user with same wins
              let prevIndex = index - 1;
              while (prevIndex > 0 && overallWins[prevIndex - 1].weekly_wins === r.weekly_wins) {
                prevIndex--;
              }
              rank = prevIndex + 1;
            }
            
            return `<tr>
              <td><strong>${rank}</strong></td>
              <td>${r.username}</td>
              <td><strong>${r.weekly_wins}</strong></td>
              <td class="muted">${r.total_correct}</td>
            </tr>`;
          }).join('') : '<tr><td colspan="4" class="muted">No data available yet.</td></tr>'}
        </tbody>
      </table>
  `;
  res.send(tplLayout('Leaderboard', body, req));
});

// Helper function to calculate weekly wins for all users
function calculateWeeklyWins() {
  // Get all weeks that have games
  const weeks = db.prepare('SELECT DISTINCT week FROM games ORDER BY week').all();
  
  const userWins = new Map();
  
  // For each week, determine winners
  for (const { week } of weeks) {
    const weeklyScores = db.prepare(`
      SELECT u.username,
             u.id,
             SUM(CASE WHEN g.winner IS NOT NULL AND p.pick = g.winner THEN 1 ELSE 0 END) AS correct
      FROM users u
      LEFT JOIN picks p ON p.user_id = u.id
      LEFT JOIN games g ON g.id = p.game_id AND g.week = ?
      WHERE g.week = ?
      GROUP BY u.id, u.username
      HAVING COUNT(p.id) > 0  -- Only include users who made picks
      ORDER BY correct DESC
    `).all(week, week);
    
    if (weeklyScores.length > 0) {
      const maxCorrect = Math.max(...weeklyScores.map(s => s.correct));
      const winners = weeklyScores.filter(s => s.correct === maxCorrect && s.correct > 0);
      
      // Award wins to all tied users
      for (const winner of winners) {
        if (!userWins.has(winner.id)) {
          userWins.set(winner.id, {
            username: winner.username,
            weekly_wins: 0,
            total_correct: 0
          });
        }
        userWins.get(winner.id).weekly_wins += 1;
      }
    }
  }
  
  // Get total correct picks for each user (for tiebreaker display)
  const totalCorrectPicks = db.prepare(`
    SELECT u.id,
           u.username,
           SUM(CASE WHEN g.winner IS NOT NULL AND p.pick = g.winner THEN 1 ELSE 0 END) AS total_correct
    FROM users u
    LEFT JOIN picks p ON p.user_id = u.id
    LEFT JOIN games g ON g.id = p.game_id
    GROUP BY u.id, u.username
  `).all();
  
  // Merge total correct picks data
  for (const user of totalCorrectPicks) {
    if (!userWins.has(user.id)) {
      userWins.set(user.id, {
        username: user.username,
        weekly_wins: 0,
        total_correct: user.total_correct || 0
      });
    } else {
      userWins.get(user.id).total_correct = user.total_correct || 0;
    }
  }
  
  // Convert to array and sort by weekly wins (desc), then total correct picks (desc), then username (asc)
  return Array.from(userWins.values())
    .sort((a, b) => {
      if (b.weekly_wins !== a.weekly_wins) {
        return b.weekly_wins - a.weekly_wins;
      }
      if (b.total_correct !== a.total_correct) {
        return b.total_correct - a.total_correct;
      }
      return a.username.localeCompare(b.username, undefined, { sensitivity: 'base' });
    });
}

// --- Admin Dashboard ---
app.get('/admin', csrfProtection, requireAuth, requireAdmin, (req, res) => {
  const week = currentWeek(req);
  const users = db.prepare('SELECT id, username, is_admin, created_at FROM users ORDER BY created_at ASC').all();
  const games = db.prepare('SELECT * FROM games WHERE week = ? ORDER BY datetime(kickoff) ASC').all(week);
  const deadline = getPickDeadline(week);
  
  const body = `
    <div class="card">
      <h1 style="margin-top:0">Admin Dashboard</h1>
      <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px;margin-bottom:20px">
        <div>
          <h3>Week ${week} Status</h3>
          <p><strong>Pick Deadline:</strong> ${deadline ? new Date(deadline).toLocaleString() : 'Not set'}</p>
          <p><strong>Games:</strong> ${games.length}</p>
          <p><strong>Can Make Picks:</strong> ${canMakePicks(week) ? 'Yes' : 'No'}</p>
        </div>
        <div>
          <h3>Quick Actions</h3>
          <div class="row" style="gap:8px;flex-wrap:wrap">
            <a href="/admin/users" class="btn">View All Users</a>
            <a href="/admin/picks?week=${week}" class="btn">View All Picks</a>
            <a href="/admin/games?week=${week}" class="btn">Manage Games</a>
          </div>
        </div>
      </div>
      
      <h3>Set Pick Deadline</h3>
      <form method="POST" action="/admin/set-deadline" style="margin-bottom:20px">
        <input type="hidden" name="_csrf" value="${req.csrfToken()}">
        <div class="row" style="gap:8px;align-items:end">
          <div>
            <label>Week</label>
            <input type="number" name="week" value="${week}" min="1" max="18" required>
          </div>
          <div>
            <label>Deadline (Date & Time)</label>
            <input type="datetime-local" name="deadline" value="${deadline ? new Date(deadline).toISOString().slice(0,16) : ''}" required>
          </div>
          <button class="btn btn-primary">Set Deadline</button>
        </div>
      </form>
      
      <h3>Fetch Games from NFL API</h3>
      <form method="POST" action="/admin/fetch-games" style="margin-bottom:20px">
        <input type="hidden" name="_csrf" value="${req.csrfToken()}">
        <div class="row" style="gap:8px;align-items:end">
          <div>
            <label>Week</label>
            <input type="number" name="week" value="${week}" min="1" max="18" required>
          </div>
          <div>
            <label>Season (optional)</label>
            <input type="number" name="season" value="2025" min="2020" max="2030">
          </div>
          <button class="btn btn-primary">Fetch Games</button>
        </div>
      </form>
      
      <h3>Update Game Results</h3>
      <form method="POST" action="/admin/update-results">
        <input type="hidden" name="_csrf" value="${req.csrfToken()}">
        <div class="row" style="gap:8px;align-items:end">
          <div>
            <label>Week</label>
            <input type="number" name="week" value="${week}" min="1" max="18" required>
          </div>
          <button class="btn btn-primary">Update Results</button>
        </div>
      </form>
      
      <h3>Registered Users</h3>
      <table style="margin-top:12px">
        <thead><tr><th>Username</th><th>Admin</th><th>Registered</th></tr></thead>
        <tbody>
          ${users.map(u => `<tr>
            <td>${u.username}</td>
            <td>${u.is_admin ? '✅ Admin' : '—'}</td>
            <td class="muted">${new Date(u.created_at).toLocaleString()}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>
  `;
  res.send(tplLayout('Admin Dashboard', body, req));
});

// --- Admin User Picks View ---
app.get('/admin/picks', csrfProtection, requireAuth, requireAdmin, (req, res) => {
  const weekParam = req.query.week;
  const week = weekParam ? parseInt(weekParam, 10) : currentWeek(req);
  
  if (isNaN(week) || week < 1 || week > 18) {
    return res.redirect(`/admin/picks?week=${currentWeek(req)}`);
  }
  
  const games = db.prepare('SELECT * FROM games WHERE week = ? ORDER BY datetime(kickoff) ASC').all(week);
  const users = db.prepare('SELECT id, username FROM users ORDER BY username').all();
  
  const body = `
    <div class="card">
      <div class="row" style="justify-content:space-between;align-items:center">
        <h1 style="margin:0">All User Picks - Week ${week}</h1>
        ${weekSelector(week, 'admin/picks')}
      </div>
      
      <table>
        <thead>
          <tr>
            <th>User</th>
            ${games.map(g => `<th>${g.away} @ ${g.home}</th>`).join('')}
            <th>Total Picks</th>
          </tr>
        </thead>
        <tbody>
          ${users.map(user => {
            const userPicks = db.prepare('SELECT game_id, pick FROM picks WHERE user_id = ? AND game_id IN (SELECT id FROM games WHERE week = ?)').all(user.id, week);
            const pickMap = new Map(userPicks.map(p => [p.game_id, p.pick]));
            const totalPicks = userPicks.length;
            
            return `<tr>
              <td><strong>${user.username}</strong></td>
              ${games.map(g => {
                const pick = pickMap.get(g.id);
                const gameResult = g.winner;
                let display = '—';
                if (pick) {
                  const isCorrect = gameResult && pick === gameResult;
                  const icon = gameResult ? (isCorrect ? '✅' : '❌') : '⏳';
                  display = `${icon} ${pick === 'away' ? g.away : g.home}`;
                }
                return `<td style="text-align:center;font-size:0.9em">${display}</td>`;
              }).join('')}
              <td style="text-align:center"><strong>${totalPicks}</strong></td>
            </tr>`;
          }).join('')}
        </tbody>
      </table>
    </div>
  `;
  res.send(tplLayout('User Picks', body, req));
});

// --- Public All Picks View ---
app.get('/all-picks', csrfProtection, requireAuth, (req, res) => {
  const weekParam = req.query.week;
  const week = weekParam ? parseInt(weekParam, 10) : currentWeek(req);

  if (isNaN(week) || week < 1 || week > 18) {
    return res.redirect(`/all-picks?week=${currentWeek(req)}`);
  }

  const games = db.prepare('SELECT * FROM games WHERE week = ? ORDER BY datetime(kickoff) ASC').all(week);
  const users = db.prepare('SELECT id, username FROM users ORDER BY username').all();

  const body = `
    <div class="card">
      <div class="row" style="justify-content:space-between;align-items:center">
        <h1 style="margin:0">All User Picks - Week ${week}</h1>
        ${weekSelector(week, 'all-picks')}
      </div>
      
      <table>
        <thead>
          <tr>
            <th>User</th>
            ${games.map(g => `<th>${g.away} @ ${g.home}</th>`).join('')}
            <th>Total Picks</th>
          </tr>
        </thead>
        <tbody>
          ${users.map(user => {
            const userPicks = db.prepare(
              'SELECT game_id, pick FROM picks WHERE user_id = ? AND game_id IN (SELECT id FROM games WHERE week = ?)'
            ).all(user.id, week);
            const pickMap = new Map(userPicks.map(p => [p.game_id, p.pick]));
            const totalPicks = userPicks.length;

            return `<tr>
              <td><strong>${user.username}</strong></td>
              ${games.map(g => {
                const pick = pickMap.get(g.id);
                const gameResult = g.winner;
                if (!pick) return `<td class="muted">—</td>`;
                
                const isCorrect = gameResult && pick === gameResult;
                const icon = gameResult ? (isCorrect ? '✅' : '❌') : '';
                return `<td>${pick === 'home' ? g.home : g.away} ${icon}</td>`;
              }).join('')}
              <td class="muted">${totalPicks}</td>
            </tr>`;
          }).join('')}
        </tbody>
      </table>
    </div>
  `;

  res.send(tplLayout('All Picks', body, req));
});


// --- Admin Users View ---
app.get('/admin/users', csrfProtection, requireAuth, requireAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT u.id, u.username, u.is_admin, u.created_at,
           COUNT(p.id) as total_picks,
           SUM(CASE WHEN g.winner IS NOT NULL AND p.pick = g.winner THEN 1 ELSE 0 END) as correct_picks
    FROM users u
    LEFT JOIN picks p ON p.user_id = u.id
    LEFT JOIN games g ON g.id = p.game_id
    GROUP BY u.id, u.username, u.is_admin, u.created_at
    ORDER BY u.created_at ASC
  `).all();
  
  const body = `
    <div class="card">
      <h1 style="margin-top:0">All Users</h1>
      <table>
        <thead>
          <tr>
            <th>Username</th>
            <th>Admin</th>
            <th>Total Picks</th>
            <th>Correct Picks</th>
            <th>Registered</th>
          </tr>
        </thead>
        <tbody>
          ${users.map(u => `<tr>
            <td><strong>${u.username}</strong></td>
            <td>${u.is_admin ? '✅ Admin' : '—'}</td>
            <td>${u.total_picks || 0}</td>
            <td>${u.correct_picks || 0}</td>
            <td class="muted">${new Date(u.created_at).toLocaleString()}</td>
          </tr>`).join('')}
        </tbody>
      </table>
      <div style="margin-top:16px">
        <a href="/admin" class="btn">Back to Admin Dashboard</a>
      </div>
    </div>
  `;
  res.send(tplLayout('All Users', body, req));
});

// --- Admin Games View ---
app.get('/admin/games', csrfProtection, requireAuth, requireAdmin, (req, res) => {
  const weekParam = req.query.week;
  const week = weekParam ? parseInt(weekParam, 10) : currentWeek(req);
  
  if (isNaN(week) || week < 1 || week > 18) {
    return res.redirect(`/admin/games?week=${currentWeek(req)}`);
  }
  
  const games = db.prepare('SELECT * FROM games WHERE week = ? ORDER BY datetime(kickoff) ASC').all(week);
  
  const body = `
    <div class="card">
      <div class="row" style="justify-content:space-between;align-items:center">
        <h1 style="margin:0">Manage Games - Week ${week}</h1>
        ${weekSelector(week, 'admin/games')}
      </div>
      
      <table>
        <thead>
          <tr>
            <th>Matchup</th>
            <th>Kickoff</th>
            <th>Score</th>
            <th>Winner</th>
            <th>Status</th>
            <th>NFL Game ID</th>
          </tr>
        </thead>
        <tbody>
          ${games.length === 0 ? '<tr><td colspan="6" class="muted">No games found for this week. Use "Fetch Games" to load from NFL API.</td></tr>' : ''}
          ${games.map(g => `<tr>
            <td><strong>${g.away} @ ${g.home}</strong></td>
            <td class="muted">${g.kickoff ? new Date(g.kickoff).toLocaleString() : '—'}</td>
            <td>${g.away_score !== null && g.home_score !== null ? `${g.away_score} - ${g.home_score}` : '—'}</td>
            <td>${g.winner ? `<strong>${g.winner === 'home' ? g.home : g.away}</strong>` : '—'}</td>
            <td class="muted">${g.status || 'scheduled'}</td>
            <td class="muted">${g.nfl_game_id || '—'}</td>
          </tr>`).join('')}
        </tbody>
      </table>
      
      <div style="margin-top:16px">
        <a href="/admin" class="btn">Back to Admin Dashboard</a>
      </div>
    </div>
  `;
  res.send(tplLayout('Manage Games', body, req));
});

// --- Admin POST Routes ---
app.post('/admin/set-deadline', csrfProtection, requireAuth, requireAdmin, (req, res) => {
  const { week, deadline } = req.body;
  if (!week || !deadline) {
    return res.status(400).send('Missing week or deadline');
  }
  
  try {
    const upsert = db.prepare('INSERT OR REPLACE INTO pick_deadlines (week, deadline) VALUES (?, ?)');
    upsert.run(parseInt(week), deadline);
    res.redirect('/admin');
  } catch (error) {
    console.error('Error setting deadline:', error);
    res.status(500).send('Error setting deadline');
  }
});

app.post('/admin/fetch-games', csrfProtection, requireAuth, requireAdmin, async (req, res) => {
  const { week, season = '2025' } = req.body;
  if (!week) {
    return res.status(400).send('Missing week');
  }
  
  try {
    const games = await fetchNFLGames(parseInt(week), parseInt(season));
    
    if (games.length === 0) {
      return res.send(tplLayout("Admin", `
        <div class="card">
          <div class="alert alert-warning">
            <h3>No games found</h3>
            <p>No games found for Week ${week}, ${season}. This might be because:</p>
            <ul>
              <li>The week hasn't been scheduled yet</li>
              <li>Invalid week/season combination</li>
              <li>ESPN API is temporarily unavailable</li>
            </ul>
          </div>
          <a href="/admin" class="btn">Back to Admin</a>
        </div>
      `, req));
    }

    const upsert = db.prepare(`
      INSERT INTO games (id, week, away, home, kickoff, nfl_game_id, status, away_score, home_score, winner)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(week, away, home) DO UPDATE SET
        kickoff = excluded.kickoff,
        nfl_game_id = excluded.nfl_game_id,
        status = excluded.status,
        away_score = excluded.away_score,
        home_score = excluded.home_score,
        winner = excluded.winner
    `);

    const tx = db.transaction(() => {
      for (const game of games) {
        const gameId = uuidv4();
        upsert.run(
          gameId, 
          parseInt(week), 
          game.away, 
          game.home, 
          game.kickoff, 
          game.nfl_game_id, 
          game.status, 
          game.away_score, 
          game.home_score, 
          game.winner
        );
      }
    });
    tx();
    
    res.redirect(`/admin?week=${week}&message=Games fetched successfully`);
  } catch (error) {
    console.error('Error fetching games:', error);
    res.status(500).send(`Error fetching games: ${error.message}`);
  }
});

// Fixed version of the /admin/update-results route
app.post('/admin/update-results', csrfProtection, requireAuth, requireAdmin, async (req, res) => {
  const { week } = req.body;
  if (!week) {
    return res.status(400).send('Missing week');
  }
  
  try {
    // Fetch fresh results from API
    const games = await fetchNFLGames(parseInt(week), 2025);
    
    if (games.length === 0) {
      return res.send(tplLayout("Admin", `
        <div class="card">
          <div class="alert alert-warning">
            <h3>No games found</h3>
            <p>No games found for Week ${week} when trying to update results.</p>
          </div>
          <a href="/admin" class="btn">Back to Admin</a>
        </div>
      `, req));
    }
    
    // Updated to match games by NFL game ID first, then fallback to team names
    const updateStmt = db.prepare(`
      UPDATE games 
      SET winner = ?, away_score = ?, home_score = ?, status = ? 
      WHERE week = ? AND (
        (nfl_game_id IS NOT NULL AND nfl_game_id = ?) OR
        (nfl_game_id IS NULL AND away = ? AND home = ?)
      )
    `);
    
    let updatedCount = 0;
    const tx = db.transaction(() => {
      for (const game of games) {
        const result = updateStmt.run(
          game.winner, 
          game.away_score, 
          game.home_score, 
          game.status, 
          parseInt(week),
          game.nfl_game_id,  // Match by NFL game ID first
          game.away,         // Fallback to team names
          game.home
        );
        if (result.changes > 0) {
          updatedCount++;
        }
      }
    });
    tx();
    
    console.log(`Updated ${updatedCount} games for week ${week}`);
    res.redirect(`/admin?week=${week}&message=Results updated successfully (${updatedCount} games)`);
  } catch (error) {
    console.error('Error updating results:', error);
    res.status(500).send(`Error updating results: ${error.message}`);
  }
});

// Handle legacy /:week routes by redirecting to query parameter format
app.get('/:week', csrfProtection, requireAuth, (req, res) => {
  const week = parseInt(req.params.week, 10);
  if (isNaN(week) || week < 1 || week > 18) {
    return res.status(400).send('Invalid week number');
  }
  res.redirect(`/?week=${week}`);
});

// Handle legacy /leaderboard/:week routes
app.get('/leaderboard/:week', csrfProtection, (req, res) => {
  const week = parseInt(req.params.week, 10);
  if (isNaN(week) || week < 1 || week > 18) {
    return res.status(400).send('Invalid week number');
  }
  res.redirect(`/leaderboard?week=${week}`);
});

// Handle legacy /games/:week routes
app.get('/games/:week', csrfProtection, (req, res) => {
  const week = parseInt(req.params.week, 10);
  if (isNaN(week) || week < 1 || week > 18) {
    return res.status(400).send('Invalid week number');
  }
  res.redirect(`/games?week=${week}`);
});

// --- 404 handler ---
app.use(csrfProtection, (req, res) => {
  res.status(404).send(tplLayout('Not found', `
    <div class="card">
      <h1>404 - Page Not Found</h1>
      <p class="muted">The page you're looking for doesn't exist.</p>
      <div style="margin-top:16px">
        <a href="/" class="btn btn-primary">Go Home</a>
      </div>
    </div>
  `, req));
});

// --- Error handling ---
app.use((error, req, res, next) => {
  console.error('App error:', error);
  
  // Handle CSRF token errors
  if (error.code === 'EBADCSRFTOKEN') {
    return res.status(403).send(tplLayout('Security Error', `
      <div class="card">
        <h1>403 - Security Error</h1>
        <p class="muted">Invalid security token. Please refresh the page and try again.</p>
        <div style="margin-top:16px">
          <a href="/" class="btn btn-primary">Go Home</a>
        </div>
      </div>
    `, req));
  }
  
  res.status(500).send(tplLayout('Server Error', `
    <div class="card">
      <h1>500 - Server Error</h1>
      <p class="muted">Something went wrong. Please try again later.</p>
      <div style="margin-top:16px">
        <a href="/" class="btn btn-primary">Go Home</a>
      </div>
    </div>
  `, req));
});

app.listen(PORT, () => {
  console.log(`NFL Picks app running at http://localhost:${PORT}`);
  console.log('');
  console.log('Features:');
  console.log('- User registration and authentication');
  console.log('- ESPN API integration for real NFL games');
  console.log('- Weekly pick deadlines');
  console.log('- Season leaderboard with weekly wins system');
  console.log('- Admin panel for managing games and users');
  console.log('- Responsive week navigation');
  console.log('');
  console.log('First registered user automatically becomes admin!');
  console.log('Visit /register to create your account and get started.');
});