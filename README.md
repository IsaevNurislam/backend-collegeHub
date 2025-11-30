# Backend Setup

## Install dependencies
```powershell
cd backend
npm install
```

## Start backend server
```powershell
npm start
```

Server will run on http://localhost:3000

## API Endpoints

### Authentication
- `POST /api/auth/login` - Login user
- `GET /api/user/me` - Get current user
- `PUT /api/user/profile` - Update profile

### News
- `GET /api/news` - Get all news
- `POST /api/news/:id/like` - Like/unlike post
- `GET /api/news/:id/comments` - Get comments
- `POST /api/news/:id/comments` - Add comment
- `PUT /api/news/:newsId/comments/:commentId` - Update comment
- `DELETE /api/news/:newsId/comments/:commentId` - Delete comment

### Clubs
- `GET /api/clubs` - Get all clubs
- `POST /api/clubs` - Create club
- `POST /api/clubs/:id/join` - Join club
- `DELETE /api/clubs/:id/leave` - Leave club

### Schedule
- `GET /api/schedule` - Get schedule
- `POST /api/schedule` - Create meeting
- `PUT /api/schedule/:id` - Update meeting
- `DELETE /api/schedule/:id` - Delete meeting

### Projects
- `GET /api/projects` - Get all projects
- `POST /api/projects` - Create project

### Parliament
- `GET /api/parliament` - Get parliament members
- `POST /api/parliament` - Admin creates a new member (name, role, position, description, groupName, avatarUrl)
- `PUT /api/parliament/:id` - Admin updates name, role, position, description, groupName, or avatarUrl
- `PUT /api/parliament/:id/avatar` - Admin updates avatar only
- `DELETE /api/parliament/:id` - Admin removes a member

### Activities
- `GET /api/activities` - Get user activities

## Default User
- Student ID: `12345`
- Password: `12345`
