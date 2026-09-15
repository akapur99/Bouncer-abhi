import Foundation

struct AppConfig {
    
    /// Supabase analytics is disabled in this fork: everything stays
    /// on-device. AnalyticsService treats an empty key as "no client".
    static let supabaseURL = ""
    static let supabaseKey = ""
} 