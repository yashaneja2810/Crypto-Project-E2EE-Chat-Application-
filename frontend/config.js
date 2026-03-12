// Configuration
window.APP_CONFIG = {
    BACKEND_URL: (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' || window.location.protocol === 'file:')
        ? 'http://localhost:3000'
        : 'https://social-media-application-7qzd.onrender.com',
    SUPABASE_URL: 'https://ethxvptzasiezviuvfwv.supabase.co',
    SUPABASE_ANON_KEY: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImV0aHh2cHR6YXNpZXp2aXV2Znd2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjcxOTg3NDIsImV4cCI6MjA4Mjc3NDc0Mn0.XikHP2O24anokFNxPs9Y1CNTbjn4xEnosVMs7KGZOSE'
};
