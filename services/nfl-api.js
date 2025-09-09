// NFL API service for fetching real game data

async function fetchTeamSchedule(teamId, season = new Date().getFullYear()) {
  const url = `https://site.api.espn.com/apis/site/v2/sports/football/nfl/teams/${teamId}/schedule?season=${season}`;
     
  try {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data = await response.json();
    return data;
  } catch (error) {
    console.error(`Error fetching team schedule for ${teamId}:`, error);
    throw error;
  }
}

async function fetchFullSeason(season = new Date().getFullYear()) {
  try {
    // NFL season typically runs from early September to late January/early February
    // Regular season is weeks 1-18, playoffs extend into February
    const startDate = `${season}0901`;  // September 1st
    const endDate = `${season + 1}0106`; // February 28th of next year (covers playoffs/Super Bowl)
    
    // Use the correct ESPN API format with date range and high limit
    const url = `https://site.api.espn.com/apis/site/v2/sports/football/nfl/scoreboard?limit=1000&dates=${startDate}-${endDate}`;
    
    console.log(`Fetching NFL games from: ${url}`);
    const response = await fetch(url);
         
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
         
    const data = await response.json();
    const games = [];
         
    if (data.events && data.events.length > 0) {
      console.log(`Found ${data.events.length} events from ESPN API`);
      
      for (const event of data.events) {
        const competition = event.competitions[0];
        const competitors = competition.competitors;
                
        const awayTeam = competitors.find(c => c.homeAway === 'away');
        const homeTeam = competitors.find(c => c.homeAway === 'home');
                
        if (awayTeam && homeTeam) {
          // Extract week number - ESPN provides this in the event object
          let week = 1;
          if (event.week && event.week.number) {
            week = event.week.number;
          } else if (event.season && event.season.slug) {
            // Fallback: try to extract from season slug or type
            const seasonType = event.season.type;
            if (seasonType === 1) { // Preseason
              week = 0;
            } else if (seasonType === 2) { // Regular season
              week = event.week ? event.week.number : 1;
            } else if (seasonType === 3) { // Playoffs
              week = 19 + (event.week ? event.week.number - 1 : 0);
            }
          }
          
          const game = {
            week: week,
            away: awayTeam.team.abbreviation,
            home: homeTeam.team.abbreviation,
            kickoff: event.date,
            status: event.status.type.name.toLowerCase(),
            away_score: awayTeam.score ? parseInt(awayTeam.score) : null,
            home_score: homeTeam.score ? parseInt(homeTeam.score) : null,
            winner: null,
            nfl_game_id: event.id
          };
                     
          // Determine winner if game is final
          if ((game.status === 'final' || game.status.includes('final')) && 
              game.away_score !== null && game.home_score !== null) {
            if (game.away_score !== game.home_score) { // Avoid ties
              game.winner = game.away_score > game.home_score ? 'away' : 'home';
            }
          }
                     
          games.push(game);
        }
      }
    } else {
      console.log('No events found in ESPN API response');
    }
         
    console.log(`Processed ${games.length} games for season ${season}`);
    return games;
  } catch (error) {
    console.error(`Error fetching full season for ${season}:`, error);
    throw error;
  }
}

// Alternative method: Fetch week by week for more reliable results
async function fetchFullSeasonByWeeks(season = new Date().getFullYear()) {
  const allGames = [];
  
  try {
    // Fetch each week individually (weeks 1-18 for regular season)
    for (let week = 1; week <= 18; week++) {
      try {
        console.log(`Fetching week ${week}...`);
        const weekGames = await fetchNFLGames(week, season);
        allGames.push(...weekGames);
        
        // Small delay to be respectful to the API
        await new Promise(resolve => setTimeout(resolve, 100));
      } catch (error) {
        console.error(`Failed to fetch week ${week}:`, error.message);
        // Continue with other weeks even if one fails
      }
    }
    
    // Optionally fetch playoff weeks (19-22)
    for (let week = 19; week <= 22; week++) {
      try {
        console.log(`Fetching playoff week ${week}...`);
        const weekGames = await fetchNFLGames(week, season);
        if (weekGames.length > 0) {
          allGames.push(...weekGames);
        }
        
        await new Promise(resolve => setTimeout(resolve, 100));
      } catch (error) {
        console.log(`No playoff games for week ${week} (this is normal)`);
        // Playoffs may not exist for all weeks, so just log and continue
      }
    }
    
    return allGames;
  } catch (error) {
    console.error(`Error in fetchFullSeasonByWeeks:`, error);
    throw error;
  }
}

async function fetchNFLGames(week, season = new Date().getFullYear()) {
  try {
    // Method 1: Try to fetch specific week using season/week parameters
    let url = `https://site.api.espn.com/apis/site/v2/sports/football/nfl/scoreboard?seasontype=2&week=${week}&season=${season}`;
    
    console.log(`Fetching week ${week} from: ${url}`);
    let response = await fetch(url);
    
    if (!response.ok) {
      // Method 2: Fallback to date-based approach
      // Estimate dates for the week (NFL typically starts first Sunday of September)
      const seasonStart = new Date(`September 1, ${season}`);
      const firstSunday = new Date(seasonStart);
      firstSunday.setDate(seasonStart.getDate() + (7 - seasonStart.getDay()) % 7);
      
      // Add weeks to get approximate week dates
      const weekStart = new Date(firstSunday);
      weekStart.setDate(firstSunday.getDate() + (week - 1) * 7);
      
      const weekEnd = new Date(weekStart);
      weekEnd.setDate(weekStart.getDate() + 6);
      
      const startDateStr = weekStart.toISOString().slice(0, 10).replace(/-/g, '');
      const endDateStr = weekEnd.toISOString().slice(0, 10).replace(/-/g, '');
      
      url = `https://site.api.espn.com/apis/site/v2/sports/football/nfl/scoreboard?dates=${startDateStr}-${endDateStr}`;
      console.log(`Fallback URL: ${url}`);
      response = await fetch(url);
    }
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    const games = [];
    
    if (data.events) {
      for (const event of data.events) {
        const competition = event.competitions[0];
        const competitors = competition.competitors;
        
        const awayTeam = competitors.find(c => c.homeAway === 'away');
        const homeTeam = competitors.find(c => c.homeAway === 'home');
        
        if (awayTeam && homeTeam) {
          // Use the week from the event if available, otherwise use requested week
          const eventWeek = event.week?.number || week;
          
          const game = {
            week: eventWeek,
            away: awayTeam.team.abbreviation,
            home: homeTeam.team.abbreviation,
            kickoff: event.date,
            status: event.status.type.name.toLowerCase(),
            away_score: awayTeam.score ? parseInt(awayTeam.score) : null,
            home_score: homeTeam.score ? parseInt(homeTeam.score) : null,
            winner: null,
            nfl_game_id: event.id
          };
          
          // Determine winner if game is final
          if ((game.status === 'final' || game.status.includes('final')) && 
              game.away_score !== null && game.home_score !== null) {
            if (game.away_score !== game.home_score) {
              game.winner = game.away_score > game.home_score ? 'away' : 'home';
            }
          }
          
          // Only include games that match the requested week (for fallback method)
          if (game.week === week) {
            games.push(game);
          }
        }
      }
    }
    
    console.log(`Found ${games.length} games for week ${week}`);
    return games;
  } catch (error) {
    console.error(`Error fetching games for week ${week}:`, error);
    throw error;
  }
}

async function populateFullSeason(season = new Date().getFullYear()) {
  const { db, uuidv4 } = require('../config/database');
     
  try {
    console.log(`Starting to populate full season ${season}...`);
    
    // Try the primary method first
    let games;
    try {
      games = await fetchFullSeason(season);
    } catch (error) {
      console.log('Primary method failed, trying week-by-week approach...');
      games = await fetchFullSeasonByWeeks(season);
    }
    
    if (games.length === 0) {
      console.log(`No games found for season ${season}`);
      return;
    }

    let insertedCount = 0;
    
    // Use transaction for bulk inserts
    const tx = db.transaction(() => {
      for (const g of games) {
        const result = db.prepare(`
          INSERT INTO games (id, week, away, home, kickoff, status, away_score, home_score, winner, nfl_game_id)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
          ON CONFLICT(week, away, home) DO NOTHING
        `).run(
          uuidv4(),
          g.week,
          g.away,
          g.home,
          g.kickoff,
          g.status,
          g.away_score,
          g.home_score,
          g.winner,
          g.nfl_game_id
        );
        if (result.changes > 0) {
          insertedCount++;
        }
      }
    });

    await tx();
    console.log(`Successfully inserted ${insertedCount} unique games for ${season} season.`);
    console.log(`Total games fetched: ${games.length}`);
  } catch (error) {
    console.error('Error populating season:', error);
    throw error;
  }
}

module.exports = {
  fetchTeamSchedule,
  fetchFullSeason,
  fetchFullSeasonByWeeks,
  fetchNFLGames,
  populateFullSeason
};