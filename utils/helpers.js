const { db } = require('../config/database');

// Import templates for requireAdmin function
const { tplLayout } = require('./templates');

// Authentication helpers
function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || !req.session.user.is_admin) {
    return res.status(403).send(tplLayout('Access Denied', `
      <div class="card">
        <h1>403 - Access Denied</h1>
        <p class="muted">You need admin privileges to access this page.</p>
        <div style="margin-top:16px">
          <a href="/" class="btn btn-primary">Go Home</a>
        </div>
      </div>
    `, req));
  }
  next();
}

// Pick deadline helpers
function canMakePicks(week) {
  try {
    // Fixed: Remove the is_active check since it doesn't exist in the schema
    const deadline = db.prepare('SELECT deadline FROM pick_deadlines WHERE week = ?').get(week);
    if (!deadline) return true; // No deadline set, allow picks
    
    const now = new Date();
    const deadlineDate = new Date(deadline.deadline);
    return now < deadlineDate;
  } catch (error) {
    console.error('Error checking pick deadline:', error);
    return true; // Default to allowing picks if there's an error
  }
}

function getPickDeadline(week) {
  try {
    // Fixed: Remove the is_active check since it doesn't exist in the schema
    const deadline = db.prepare('SELECT deadline FROM pick_deadlines WHERE week = ?').get(week);
    return deadline ? deadline.deadline : null;
  } catch (error) {
    console.error('Error getting pick deadline:', error);
    return null;
  }
}

// Updated weekSelector function with proper redirects
function weekSelector(currentWeek, basePath = '') {
  const weeks = Array.from({ length: 18 }, (_, i) => i + 1);
  
  return `
    <div class="week-selector" style="display:flex;gap:4px;align-items:center;flex-wrap:wrap">
      <span class="muted" style="margin-right:8px">Week:</span>
      ${weeks.map(week => {
        const isActive = week === currentWeek;
        const buttonStyle = isActive 
          ? 'background:#3b82f6;color:white;border:1px solid #3b82f6'
          : 'background:#f8fafc;color:#374151;border:1px solid #d1d5db';
        
        // Determine the correct URL based on basePath
        let url;
        if (basePath === 'home' || basePath === '') {
          url = `/?week=${week}`;
        } else if (basePath === 'games') {
          url = `/games?week=${week}`;
        } else if (basePath === 'leaderboard') {
          url = `/leaderboard?week=${week}`;
        } else if (basePath === 'admin/picks') {
          url = `/admin/picks?week=${week}`;
        } else if (basePath === 'admin/games') {
          url = `/admin/games?week=${week}`;
        } else {
          url = `/${basePath}?week=${week}`;
        }
        
        return `<a href="${url}" class="btn" style="${buttonStyle};padding:4px 8px;text-decoration:none;border-radius:4px;font-size:0.9em;min-width:24px;text-align:center">${week}</a>`;
      }).join('')}
    </div>
  `;
}

// Current week helper - fixed to include max week validation
function currentWeek(req) {
  const w = parseInt(req.query.week || '1', 10);
  return Number.isFinite(w) && w > 0 && w <= 18 ? w : 1;
}

module.exports = {
  requireAuth,
  requireAdmin,
  canMakePicks,
  getPickDeadline,
  weekSelector,
  currentWeek
};