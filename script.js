/* =========================================================
   THADAM LABS – AI-POWERED EMAIL THREAT DETECTION
   COMPLETE CLIENTSIDE LOGIC & STATE ENGINE
========================================================= */

"use strict";

/* =========================================================
   1. CONSTANTS & STORAGE KEYS
========================================================= */

const STORAGE_KEY = "thadam_labs_security_store_v2";

const IMPORTANT_KEYWORDS = [
    "college",
    "internship",
    "project",
    "submission",
    "faculty",
    "scholarship",
    "exam",
    "placement",
    "assignment",
    "meeting",
    "university",
    "campus",
    "dean",
    "professor"
];

const SUSPICIOUS_KEYWORDS = [
    "verify", "verification", "urgent", "immediately", "password", "account",
    "suspended", "suspension", "winner", "prize", "claim", "click here",
    "limited offer", "payment", "bank", "login", "confirm", "security alert",
    "act now", "action required", "credit card", "billing", "unauthorized",
    "compromised", "lottery", "gift card", "crypto", "bitcoin", "tax refund",
    "wire transfer", "authenticate", "deactivation"
];

const TRUSTED_DOMAINS = [
    "college.edu",
    "university.edu",
    "projectmail.com",
    "thadamlabs.com",
    "github.com",
    "google.com"
];

const SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".ru", ".click", ".live", ".loan", ".work",
    ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".cam", ".info", ".net"
];

const SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "goo.gl", "cutt.ly"
];


/* =========================================================
   2. INITIAL DEMO DATA SEED (128 ANALYSED, 12 THREATS, 46 SPAM, 18 IMPORTANT)
========================================================= */

const INITIAL_DEMO_EMAILS = [
    // --- 3 IMPORTANT EMAILS MISPLACED IN SPAM (PROTOTYPE REQUIREMENT) ---
    {
        id: "eml-101",
        sender: "placement@college.edu",
        subject: "College Internship Update",
        body: "Dear Student,\n\nYour application for the Summer Internship Program 2026 has been reviewed by the placement cell and academic faculty.\n\nPlease submit your updated resume and project repository link by Friday.\n\nBest regards,\nPlacement Coordination Office\nCollege of Engineering",
        folder: "spam",
        category: "Safe",
        score: 12,
        reasons: ["Legitimate academic domain (.edu)", "Zero malicious links detected"],
        isImportant: true,
        date: "10:32 AM",
        timestamp: Date.now() - 3600000 * 2,
        flaggedInSpam: true
    },
    {
        id: "eml-102",
        sender: "faculty@college.edu",
        subject: "Project Submission Reminder",
        body: "Attention Students,\n\nThis is a final reminder that the Capstone Project Phase 1 submission portal will close tonight at 11:59 PM.\n\nEnsure all source code files and documentation are pushed to your team repository.\n\nRegards,\nFaculty Project Coordinator",
        folder: "spam",
        category: "Safe",
        score: 14,
        reasons: ["Recognized university sender", "Standard institutional announcement"],
        isImportant: true,
        date: "Yesterday",
        timestamp: Date.now() - 3600000 * 26,
        flaggedInSpam: true
    },
    {
        id: "eml-103",
        sender: "scholarships@college.edu",
        subject: "Scholarship Application Update",
        body: "Dear Applicant,\n\nThe State Merit Scholarship verification list has been published. Please visit the financial aid office with your student identity card to confirm your allotment.\n\nDean of Student Affairs",
        folder: "spam",
        category: "Safe",
        score: 10,
        reasons: ["Verified college domain", "No external URLs"],
        isImportant: true,
        date: "Sep 7",
        timestamp: Date.now() - 3600000 * 48,
        flaggedInSpam: true
    },

    // --- INBOX LEGITIMATE EMAILS ---
    {
        id: "eml-104",
        sender: "team@projectmail.com",
        subject: "Team Meeting",
        body: "Hi team,\n\nOur sprint retrospective and architecture review is scheduled for tomorrow at 2:00 PM in Conference Room B.\n\nPlease review the sprint backlog before attending.\n\nThanks,\nProject Lead",
        folder: "inbox",
        category: "Safe",
        score: 8,
        reasons: ["Known collaborator sender", "Safe clean text body"],
        isImportant: false,
        date: "Sep 7",
        timestamp: Date.now() - 3600000 * 50,
        flaggedInSpam: false
    },
    {
        id: "eml-105",
        sender: "exam.cell@college.edu",
        subject: "Mid-Term Examination Schedule",
        body: "Dear Students,\n\nThe timetable for the upcoming mid-term semester examinations has been published on the official college intranet. Please check your hall tickets.\n\nExam Controller",
        folder: "inbox",
        category: "Safe",
        score: 10,
        reasons: ["Official college.edu domain", "No suspicious attributes"],
        isImportant: true,
        date: "Sep 6",
        timestamp: Date.now() - 3600000 * 72,
        flaggedInSpam: false
    },
    {
        id: "eml-125",
        sender: "careers@college.edu",
        subject: "Campus Placement Drive Registration",
        body: "Dear Students,\n\nRegistrations are now open for the upcoming Microsoft and Google campus recruitment sessions. Eligibility criteria and interview guidelines are attached on the college portal.\n\nPlacement Cell",
        folder: "inbox",
        category: "Safe",
        score: 12,
        reasons: ["Official institutional correspondence", "Trusted university communication"],
        isImportant: true,
        date: "Sep 5",
        timestamp: Date.now() - 3600000 * 96,
        flaggedInSpam: false
    },
    {
        id: "eml-126",
        sender: "mentorship@college.edu",
        subject: "Faculty Mentorship Schedule & Review",
        body: "Hello,\n\nPlease confirm your scheduled appointment with your assigned faculty mentor for your semester project guidance.\n\nAcademic Office",
        folder: "inbox",
        category: "Safe",
        score: 10,
        reasons: ["Recognized college staff sender"],
        isImportant: true,
        date: "Sep 4",
        timestamp: Date.now() - 3600000 * 110,
        flaggedInSpam: false
    },
    {
        id: "eml-127",
        sender: "council@college.edu",
        subject: "Student Council Hackathon Announcement",
        body: "Greetings,\n\nJoin the annual 36-hour Hackathon. Teams can register up to 4 members. Prizes worth $5,000 to be won!\n\nStudent Council",
        folder: "inbox",
        category: "Safe",
        score: 14,
        reasons: ["Internal campus announcement"],
        isImportant: false,
        date: "Sep 3",
        timestamp: Date.now() - 3600000 * 130,
        flaggedInSpam: false
    },

    // --- 12 THREATS DETECTED (EXACTLY 4 HIGH, 5 MEDIUM, 3 LOW) ---
    // High Threat 1
    {
        id: "eml-106",
        sender: "unknown.sender@gmail.com",
        subject: "Account Verification Required",
        body: "URGENT SECURITY ALERT!\n\nYour online account requires immediate verification. We have detected suspicious login attempts from an unknown IP address.\n\nClick here immediately to confirm your password and avoid permanent account suspension: http://bit.ly/secure-verify-acc902\n\nFailure to verify within 12 hours will result in termination.",
        folder: "inbox",
        category: "Suspicious",
        score: 78,
        isThreat: true,
        reasons: [
            "Suspicious shortened URL detected (bit.ly)",
            "High urgency phishing keywords (urgent, suspended, confirm password)",
            "Unverified external sender using free mail provider"
        ],
        isImportant: false,
        date: "Yesterday",
        timestamp: Date.now() - 3600000 * 28,
        flaggedInSpam: false
    },
    // High Threat 2
    {
        id: "eml-107",
        sender: "security-alert@random-banking-update.com",
        subject: "Urgent Account Alert: Access Frozen",
        body: "DEAR VALUED CUSTOMER,\n\nYOUR BANK ACCOUNT ACCESS HAS BEEN TEMPORARILY FROZEN DUE TO SUSPICIOUS ACTIVITY.\n\nYOU MUST IMMEDIATELY LOGIN AND VERIFY YOUR IDENTITY AND CREDIT CARD DETAILS TO UNLOCK YOUR FUNDS:\nhttp://192.168.1.104/secure/login?action=confirm\n\nDO NOT IGNORE THIS WARNING.",
        folder: "inbox",
        category: "Harmful",
        score: 91,
        isThreat: true,
        reasons: [
            "Direct IP address URL detected (http://192.168...)",
            "Severe financial credential harvesting patterns",
            "Excessive capitalization and coercive urgency",
            "Insecure HTTP protocol used for authentication target"
        ],
        isImportant: false,
        date: "Sep 7",
        timestamp: Date.now() - 3600000 * 55,
        flaggedInSpam: false
    },
    // High Threat 3
    {
        id: "eml-116",
        sender: "hr-payroll@external-workforce.xyz",
        subject: "Payroll Direct Deposit Verification",
        body: "Employee Notice:\n\nYour direct deposit payroll routing has failed verification. You must immediately confirm your banking credentials and password at http://portal-payroll-update.xyz/login to receive your paycheck on schedule.",
        folder: "inbox",
        category: "Harmful",
        score: 85,
        isThreat: true,
        reasons: [
            "High-risk top-level domain (.xyz)",
            "Requests for sensitive banking and payroll credentials",
            "Deceptive psychological financial coercion"
        ],
        isImportant: false,
        date: "Sep 7",
        timestamp: Date.now() - 3600000 * 52,
        flaggedInSpam: false
    },
    // High Threat 4
    {
        id: "eml-117",
        sender: "admin-support@it-security-auth.net",
        subject: "Critical IT Security Patch Required",
        body: "All staff: Urgent critical malware vulnerability detected on your workstation. Download and run the security patch immediately from: http://security-update-agent.net/patch.exe",
        folder: "inbox",
        category: "Harmful",
        score: 82,
        isThreat: true,
        reasons: [
            "Executable attachment / binary payload URL (.exe)",
            "Impersonating internal IT security staff",
            "Insecure unencrypted HTTP download target"
        ],
        isImportant: false,
        date: "Sep 6",
        timestamp: Date.now() - 3600000 * 70,
        flaggedInSpam: false
    },

    // Medium Threat 1
    {
        id: "eml-108",
        sender: "billing@unknownmail.com",
        subject: "Payment Confirmation Required",
        body: "Hello,\n\nWe were unable to process your recurring subscription payment of $89.99.\n\nPlease update your credit card and billing details here: http://unknownmail-billing.com/pay\n\nThank you,\nBilling Department",
        folder: "inbox",
        category: "Suspicious",
        score: 54,
        isThreat: true,
        reasons: [
            "Unverified sender domain with billing solicitation",
            "Insecure HTTP link detected",
            "Unsolicited invoice claim"
        ],
        isImportant: false,
        date: "Sep 6",
        timestamp: Date.now() - 3600000 * 80,
        flaggedInSpam: false
    },
    // Medium Threat 2
    {
        id: "eml-118",
        sender: "tracking@parcel-express-delivery.xyz",
        subject: "Unclaimed Package Tracking Alert #US-9821",
        body: "Your parcel delivery could not be completed due to incorrect address information. Click here to confirm delivery details: http://parcel-express-delivery.xyz/track?id=9821",
        folder: "inbox",
        category: "Suspicious",
        score: 62,
        isThreat: true,
        reasons: [
            "Suspicious .xyz domain",
            "Generic unverified courier tracking link",
            "Unsolicited delivery alert"
        ],
        isImportant: false,
        date: "Sep 5",
        timestamp: Date.now() - 3600000 * 90,
        flaggedInSpam: false
    },
    // Medium Threat 3
    {
        id: "eml-119",
        sender: "refund-portal@tax-claim-gov.top",
        subject: "Action Required: Tax Refund Verification",
        body: "You have an outstanding tax refund of $480.00 ready for electronic transfer. Verify your identity and social security number at http://tax-claim-gov.top/refund immediately.",
        folder: "inbox",
        category: "Suspicious",
        score: 66,
        isThreat: true,
        reasons: [
            "Suspicious .top top-level domain",
            "Government agency impersonation tactics",
            "Requests for sensitive personal identification numbers"
        ],
        isImportant: false,
        date: "Sep 5",
        timestamp: Date.now() - 3600000 * 94,
        flaggedInSpam: false
    },
    // Medium Threat 4
    {
        id: "eml-120",
        sender: "cloud-share@docu-sign-verify.com",
        subject: "Shared Document Notification: Confidential Agreement",
        body: "A confidential document has been shared with you. Click below to review and sign:\nhttp://docu-sign-verify.com/view/doc-7721\nLink expires in 24 hours.",
        folder: "inbox",
        category: "Suspicious",
        score: 59,
        isThreat: true,
        reasons: [
            "Deceptive service impersonation (docu-sign)",
            "Redirect target domain differs from authentic provider",
            "Arbitrary artificial expiration urgency"
        ],
        isImportant: false,
        date: "Sep 4",
        timestamp: Date.now() - 3600000 * 115,
        flaggedInSpam: false
    },
    // Medium Threat 5
    {
        id: "eml-121",
        sender: "accounting@quick-wire-transfer.live",
        subject: "Wire Transfer Confirmation Receipt #WT-5501",
        body: "Your outgoing wire transfer of $4,250.00 to account ending in 9012 is processing. If you did not authorize this payment, cancel immediately at http://quick-wire-transfer.live/cancel.",
        folder: "inbox",
        category: "Suspicious",
        score: 64,
        isThreat: true,
        reasons: [
            "Financial panic trigger pattern",
            "Suspicious .live domain with insecure HTTP",
            "Unsolicited payment notification"
        ],
        isImportant: false,
        date: "Sep 4",
        timestamp: Date.now() - 3600000 * 120,
        flaggedInSpam: false
    },

    // Low Threat 1
    {
        id: "eml-122",
        sender: "billing-notice@digital-renewals.work",
        subject: "Your Subscription Invoice #8921",
        body: "Your annual software subscription has renewed automatically. View your invoice here: http://digital-renewals.work/invoices/8921",
        folder: "inbox",
        category: "Spam",
        score: 38,
        isThreat: true,
        reasons: [
            "Non-standard .work top-level domain",
            "Unsolicited invoice notification",
            "Insecure HTTP destination"
        ],
        isImportant: false,
        date: "Sep 3",
        timestamp: Date.now() - 3600000 * 140,
        flaggedInSpam: false
    },
    // Low Threat 2
    {
        id: "eml-123",
        sender: "rewards@shopping-club-bonus.buzz",
        subject: "Unusual Activity on Loyalty Points",
        body: "Your shopping loyalty points balance of 1,200 points will expire at midnight. Log in to redeem your coupon: http://shopping-club-bonus.buzz/claim",
        folder: "inbox",
        category: "Spam",
        score: 42,
        isThreat: true,
        reasons: [
            "Suspicious .buzz top-level domain",
            "Marketing urgency pressure"
        ],
        isImportant: false,
        date: "Sep 3",
        timestamp: Date.now() - 3600000 * 145,
        flaggedInSpam: false
    },
    // Low Threat 3
    {
        id: "eml-124",
        sender: "survey-bot@analytics-panel.click",
        subject: "Invitation: Global Cyber Defense Survey",
        body: "Participate in our 3-minute survey and receive a $10 coffee coupon. Complete the survey here: http://analytics-panel.click/survey",
        folder: "inbox",
        category: "Spam",
        score: 35,
        isThreat: true,
        reasons: [
            "Unknown marketing research sender",
            "Incentivized survey solicitation"
        ],
        isImportant: false,
        date: "Sep 2",
        timestamp: Date.now() - 3600000 * 160,
        flaggedInSpam: false
    },

    // --- SPAM EMAILS (INCLUDING REPEATED SPAM SENDER: deals@megapromo.com) ---
    {
        id: "eml-109",
        sender: "offers@randommail.com",
        subject: "Special Offer Just For You",
        body: "Congratulations! You have been selected to receive a complimentary luxury vacation package. Claim your exclusive rewards points now before they expire!",
        folder: "spam",
        category: "Spam",
        score: 46,
        reasons: ["Unsolicited marketing promotional language", "Generic prize reward promises"],
        isImportant: false,
        date: "10:45 AM",
        timestamp: Date.now() - 3600000 * 3,
        flaggedInSpam: false
    },
    {
        id: "eml-110",
        sender: "promo@unknown.com",
        subject: "Congratulations! You Won a Prize",
        body: "You are the lucky winner of our $1,000 gift card lottery draw! Click here to claim your cash reward immediately!",
        folder: "spam",
        category: "Spam",
        score: 58,
        reasons: ["Classic lottery scam format", "Prize claim keyword triggers"],
        isImportant: false,
        date: "Sep 7",
        timestamp: Date.now() - 3600000 * 60,
        flaggedInSpam: false
    },
    {
        id: "eml-111",
        sender: "deals@megapromo.com",
        subject: "Exclusive 90% Discount Just For You",
        body: "Huge clearance sale! Up to 90% off all electronic items. Click now to order.",
        folder: "spam",
        category: "Spam",
        score: 48,
        reasons: ["Unsolicited commercial email", "Frequent mass promo"],
        isImportant: false,
        date: "Today",
        timestamp: Date.now() - 3600000 * 1,
        flaggedInSpam: false
    },
    {
        id: "eml-112",
        sender: "deals@megapromo.com",
        subject: "Final Hour: Claim Your Free Gift Card",
        body: "Don't miss out on your $50 shopping voucher! Claim your bonus now.",
        folder: "spam",
        category: "Spam",
        score: 52,
        reasons: ["Urgent marketing offer", "Repeated unwanted sender"],
        isImportant: false,
        date: "Yesterday",
        timestamp: Date.now() - 3600000 * 20,
        flaggedInSpam: false
    },
    {
        id: "eml-113",
        sender: "deals@megapromo.com",
        subject: "Flash Sale Ends Tonight!",
        body: "Midnight special coupons available now. Shop your favorite deals before inventory is gone.",
        folder: "spam",
        category: "Spam",
        score: 46,
        reasons: ["Marketing newsletter", "Repeated unwanted sender"],
        isImportant: false,
        date: "Sep 7",
        timestamp: Date.now() - 3600000 * 58,
        flaggedInSpam: false
    },
    {
        id: "eml-114",
        sender: "deals@megapromo.com",
        subject: "You Have 1 Unclaimed Reward",
        body: "Reminder: You still have an unclaimed mystery gift waiting in your shopping cart.",
        folder: "spam",
        category: "Spam",
        score: 50,
        reasons: ["Spam incentive", "Repeated unwanted sender"],
        isImportant: false,
        date: "Sep 6",
        timestamp: Date.now() - 3600000 * 75,
        flaggedInSpam: false
    },
    {
        id: "eml-115",
        sender: "offers@mail.com",
        subject: "Suspicious Newsletter",
        body: "Weekly curated digests and special sponsor messages. Click here to unsubscribe.",
        folder: "spam",
        category: "Safe",
        score: 28,
        reasons: ["Low risk promotional bulk mail", "Valid unsubscribe header"],
        isImportant: false,
        date: "Sep 5",
        timestamp: Date.now() - 3600000 * 95,
        flaggedInSpam: false
    }
];


/* =========================================================
   3. CENTRAL APP STATE
========================================================= */

const appState = {
    currentPage: "dashboard",
    emails: [],
    blockedSenders: ["scam-bot@phishmail.ru"],
    stats: {
        analysed: 128,
        threats: 12,
        spam: 46,
        important: 18
    },
    notifications: [
        { id: 1, text: "Thadam Labs threat detection engine activated", time: "Just now" },
        { id: 2, text: "3 important emails identified in Spam folder", time: "10 mins ago" },
        { id: 3, text: "Repeated spammer detected: deals@megapromo.com", time: "1 hr ago" }
    ],
    activeAnalysisResult: null,
    searchQueries: {
        inbox: "",
        spam: "",
        threats: "",
        important: ""
    },
    settings: {
        aggressiveLinks: true,
        keywordRecovery: true
    }
};


/* =========================================================
   4. STORAGE MANAGEMENT (PERSISTENCE)
========================================================= */

function loadFromStorage() {
    try {
        const savedData = localStorage.getItem(STORAGE_KEY);
        if (savedData) {
            const parsed = JSON.parse(savedData);
            if (Array.isArray(parsed.emails) && parsed.emails.length > 0) {
                appState.emails = parsed.emails;
                appState.blockedSenders = Array.isArray(parsed.blockedSenders) ? parsed.blockedSenders : [];
                if (parsed.stats && typeof parsed.stats.analysed === "number") {
                    appState.stats = parsed.stats;
                } else {
                    appState.stats = {
                        analysed: typeof parsed.analysedCount === "number" ? parsed.analysedCount : 128,
                        threats: 12,
                        spam: 46,
                        important: 18
                    };
                }
                appState.notifications = Array.isArray(parsed.notifications) ? parsed.notifications : [];
                if (parsed.settings) appState.settings = parsed.settings;
                return;
            }
        }
    } catch (err) {
        console.warn("Could not read local storage, initializing default demo state:", err);
    }

    // Seed defaults
    appState.emails = JSON.parse(JSON.stringify(INITIAL_DEMO_EMAILS));
    appState.stats = {
        analysed: 128,
        threats: 12,
        spam: 46,
        important: 18
    };
    saveToStorage();
}

function saveToStorage() {
    try {
        const payload = {
            emails: appState.emails,
            blockedSenders: appState.blockedSenders,
            stats: appState.stats,
            notifications: appState.notifications,
            settings: appState.settings
        };
        localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
    } catch (err) {
        console.error("Failed saving to localStorage:", err);
    }
}

function resetToDefaultData() {
    if (confirm("Reset application data back to factory demo state?")) {
        localStorage.removeItem(STORAGE_KEY);
        loadFromStorage();
        updateAllStatsAndBadges();
        renderCurrentPage();
        renderBlockedSendersList();
        closeSettingsModal();
        showToast("Demo data restored successfully.", "success");
    }
}

function clearAllData() {
    if (confirm("Warning: Clear all saved emails and local storage?")) {
        appState.emails = [];
        appState.blockedSenders = [];
        appState.stats = { analysed: 0, threats: 0, spam: 0, important: 0 };
        appState.notifications = [];
        saveToStorage();
        updateAllStatsAndBadges();
        renderCurrentPage();
        renderBlockedSendersList();
        closeSettingsModal();
        showToast("All data wiped.", "error");
    }
}


/* =========================================================
   5. REPEATED SPAM & IMPORTANT EMAIL ENGINE
========================================================= */

/**
 * Counts how many unwanted emails a sender has.
 * Returns true if sender has >= 3 spam emails.
 */
function isRepeatedSpammer(senderEmail) {
    if (!senderEmail) return false;
    const cleanSender = extractEmailAddress(senderEmail).toLowerCase().trim();
    const count = appState.emails.filter(e =>
        e.folder === "spam" &&
        e.sender &&
        extractEmailAddress(e.sender).toLowerCase().trim() === cleanSender
    ).length;
    return count >= 3;
}

/**
 * Extracts pure email address from strings formatted as "Name <email@domain.com>"
 */
function extractEmailAddress(raw) {
    if (!raw) return "";
    const match = raw.match(/<([^>]+)>/);
    return match ? match[1].trim() : raw.trim();
}

/**
 * Checks if an email is important (contains college/internship keywords).
 */
function isEmailImportant(email) {
    if (email.isImportant) return true;
    const textToScan = `${email.subject || ""} ${email.body || ""}`.toLowerCase();
    return IMPORTANT_KEYWORDS.some(kw => textToScan.includes(kw));
}

/**
 * Scans emails in Spam to identify those containing important keywords.
 */
function getImportantEmailsInSpam() {
    return appState.emails.filter(e =>
        e.folder === "spam" &&
        isEmailImportant(e)
    );
}

/**
 * Gets all threats (Suspicious, Harmful, or flagged as threat).
 */
function getAllThreats() {
    return appState.emails.filter(e =>
        e.isThreat === true ||
        e.category === "Suspicious" ||
        e.category === "Harmful" ||
        e.score >= 61
    );
}


/* =========================================================
   6. RULE-BASED THREAT DETECTION ENGINE
========================================================= */

/**
 * Evaluates raw email text, sender, and subject to generate a 0-100 score
 * and classify into SAFE (0-30), SPAM (31-60), SUSPICIOUS (61-80), HARMFUL (81-100).
 */
function calculateThreatScore(rawText, sender = "", subject = "") {
    let score = 5;
    const reasons = [];
    const content = `${subject}\n${rawText}`.trim();
    const lower = content.toLowerCase();
    const cleanSender = (sender || "").toLowerCase().trim();
    const senderEmail = extractEmailAddress(cleanSender);
    const senderDomain = senderEmail.includes("@") ? senderEmail.split("@")[1] : "";

    // Factor 1: Blocked Sender Check
    if (senderEmail && appState.blockedSenders.some(b => senderEmail.includes(b.toLowerCase()))) {
        score += 50;
        reasons.push("Sender address is listed in your Blocked Senders directory");
    }

    // Factor 2: Suspicious Links Indicators
    const urls = content.match(/https?:\/\/[^\s<>"']+/gi) || [];

    if (urls.length > 0) {
        score += 15;

        // Multiple URLs
        if (urls.length >= 3) {
            score += 10;
            reasons.push(`Multiple hyperlink redirects detected (${urls.length} URLs)`);
        }

        // Insecure HTTP targets
        const insecureHttp = urls.some(u => u.startsWith("http://"));
        if (insecureHttp) {
            score += 15;
            reasons.push("Insecure unencrypted HTTP destination link detected");
        }

        // URL Shorteners
        const hasShortener = urls.some(u =>
            SHORTENER_DOMAINS.some(d => u.toLowerCase().includes(d))
        );
        if (hasShortener) {
            score += 20;
            reasons.push("URL shortener used to conceal true destination domain");
        }

        // Direct IP Address in URL
        const hasIpUrl = urls.some(u => /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(u));
        if (hasIpUrl) {
            score += 25;
            reasons.push("Direct numerical IP host in URL – strong malware/phishing indicator");
        }

        // Suspicious keywords in URLs
        const urlKeywords = ["login", "verify", "secure", "account", "update", "bank", "confirm", "auth", "payment", "pwd"];
        const hasUrlKw = urls.some(u => urlKeywords.some(kw => u.toLowerCase().includes(kw)));
        if (hasUrlKw) {
            score += 15;
            reasons.push("Link contains credential/banking harvest terminology");
        }

        // Domain mismatch between apparent sender domain and link destination
        if (senderDomain) {
            const hasMismatch = urls.some(u => {
                try {
                    const parsedUrl = new URL(u);
                    const linkHost = parsedUrl.hostname.toLowerCase();
                    return !linkHost.includes(senderDomain) && !senderDomain.includes(linkHost);
                } catch {
                    return false;
                }
            });
            if (hasMismatch && !TRUSTED_DOMAINS.some(d => senderDomain.includes(d))) {
                score += 15;
                reasons.push("Domain mismatch: Link destination does not match sender domain");
            }
        }
    }

    // Factor 3: Suspicious & Urgency Keywords
    const foundKeywords = SUSPICIOUS_KEYWORDS.filter(kw => lower.includes(kw));
    if (foundKeywords.length > 0) {
        const addedScore = Math.min(30, foundKeywords.length * 6);
        score += addedScore;
        const kwSnippet = foundKeywords.slice(0, 3).join(", ");
        reasons.push(`High-risk urgency keywords detected (${kwSnippet})`);
    }

    // Factor 4: Financial & Scam Rewards
    const scamPhrases = [
        "won a prize", "claim your reward", "lottery", "gift card",
        "free money", "wire transfer", "inheritance", "bitcoin payment",
        "cash reward", "mystery gift", "unclaimed bonus"
    ];
    if (scamPhrases.some(p => lower.includes(p))) {
        score += 20;
        reasons.push("Unsolicited lottery, prize, or cryptocurrency payment promises");
    }

    // Factor 5: Account Suspension & Security Threat Language
    const threatPhrases = [
        "account suspended", "temporarily frozen", "terminated within",
        "failure to verify", "unauthorized access", "immediately verify",
        "permanently closed", "deactivation notice"
    ];
    if (threatPhrases.some(p => lower.includes(p))) {
        score += 20;
        reasons.push("Coercive psychological urgency and account suspension threats");
    }

    // Factor 6: Requests for Sensitive Credentials
    const credPhrases = [
        "enter your password", "confirm your password", "social security",
        "credit card number", "banking credentials", "pin number"
    ];
    if (credPhrases.some(p => lower.includes(p))) {
        score += 20;
        reasons.push("Requests for sensitive passwords or financial credentials");
    }

    // Factor 7: Suspicious Attachment Indicators
    const dangerousExts = [".exe", ".scr", ".bat", ".vbs", ".cmd", ".iso", ".zip"];
    const hasDangerExt = dangerousExts.some(ext => lower.includes(ext));
    if (hasDangerExt) {
        score += 25;
        reasons.push("Dangerous binary / executable payload reference (.exe, .scr, .zip)");
    }

    // Factor 8: Sender Reputation & Domain Analysis
    if (senderEmail) {
        const isTrusted = TRUSTED_DOMAINS.some(d => senderEmail.includes(d));
        if (isTrusted) {
            score = Math.max(0, score - 20);
            reasons.push("Sender originates from recognized trusted organization");
        } else {
            // Check suspicious TLDs
            const hasSuspiciousTld = SUSPICIOUS_TLDS.some(tld => senderEmail.endsWith(tld));
            if (hasSuspiciousTld) {
                score += 25;
                reasons.push("Sender address uses high-risk or disposable top-level domain");
            }

            // Random-looking or heavily obfuscated sender
            const localPart = senderEmail.split("@")[0] || "";
            if (/[0-9]{4,}/.test(localPart) || /[a-z0-9]{12,}/.test(localPart)) {
                score += 15;
                reasons.push("Randomized or machine-generated sender address pattern");
            }
        }
    } else {
        score += 10;
        reasons.push("Missing or obfuscated sender address");
    }

    // Factor 9: Excessive Capitalization
    const letters = (content.match(/[a-zA-Z]/g) || []).length;
    const uppercase = (content.match(/[A-Z]/g) || []).length;
    if (letters > 25 && uppercase / letters > 0.45) {
        score += 10;
        reasons.push("Excessive capitalization indicating spam pressure tactics");
    }

    // Clamp score between 0 and 100
    score = Math.max(0, Math.min(100, Math.round(score)));

    // Categorization according to prompt specification:
    // 0–30 = SAFE, 31–60 = SPAM, 61–80 = SUSPICIOUS, 81–100 = HARMFUL
    let category = "Safe";
    if (score >= 81) {
        category = "Harmful";
    } else if (score >= 61) {
        category = "Suspicious";
    } else if (score >= 31) {
        category = "Spam";
    }

    if (reasons.length === 0) {
        reasons.push("Clean email headers and standard correspondence structure");
    }

    return { score, category, reasons };
}

/**
 * Extracts basic headers from raw text.
 */
function parseRawEmailHeaders(rawText) {
    const subjectMatch = rawText.match(/^Subject\s*:\s*(.+)$/im);
    const fromMatch = rawText.match(/^From\s*:\s*(.+)$/im);

    let sender = fromMatch ? fromMatch[1].trim() : "";
    let subject = subjectMatch ? subjectMatch[1].trim() : "";

    // Clean body by removing From and Subject lines if present at top
    let body = rawText
        .replace(/^Subject\s*:\s*.+$/im, "")
        .replace(/^From\s*:\s*.+$/im, "")
        .trim();

    if (!sender) sender = "unknown.sender@gmail.com";
    if (!subject) subject = "No Subject";
    if (!body) body = rawText;

    return { sender, subject, body };
}


/* =========================================================
   7. NAVIGATION & PAGE SWITCHING
========================================================= */

function showPage(pageId) {
    const page = document.getElementById(pageId);
    if (!page) return;

    // Toggle pages
    document.querySelectorAll(".page").forEach(p => p.classList.remove("active-page"));
    page.classList.add("active-page");
    appState.currentPage = pageId;

    // Update page title in topbar
    const titleMap = {
        dashboard: "Dashboard",
        analysis: "Email Analysis",
        threatResult: "Threat Result",
        inbox: "Inbox",
        spam: "Spam",
        threats: "Threats",
        important: "Important Emails",
        reports: "Reports"
    };
    const titleEl = document.getElementById("pageTitle");
    if (titleEl) titleEl.textContent = titleMap[pageId] || "Dashboard";

    // Update sidebar active classes
    document.querySelectorAll("#mainNavigation .nav-item").forEach(link => {
        if (link.getAttribute("data-page") === pageId) {
            link.classList.add("active");
        } else {
            link.classList.remove("active");
        }
    });

    // Close mobile drawer if open
    toggleSidebar(false);

    // Refresh contents
    renderCurrentPage();
    updateAllStatsAndBadges();

    window.scrollTo({ top: 0, behavior: "smooth" });
}

function renderCurrentPage() {
    switch (appState.currentPage) {
        case "dashboard":
            renderDashboard();
            break;
        case "inbox":
            renderInbox();
            break;
        case "spam":
            renderSpam();
            break;
        case "threats":
            renderThreats();
            break;
        case "important":
            renderImportant();
            break;
        case "reports":
            renderReports();
            break;
        case "threatResult":
            if (appState.activeAnalysisResult) {
                renderThreatResultView(appState.activeAnalysisResult);
            }
            break;
    }
}


/* =========================================================
   8. RENDERING FUNCTIONS
========================================================= */

// --- Dashboard ---
function renderDashboard() {
    const impContainer = document.getElementById("dashboardImportantList");
    if (!impContainer) return;

    const importantSpamEmails = getImportantEmailsInSpam().slice(0, 3);

    if (importantSpamEmails.length === 0) {
        impContainer.innerHTML = `
            <div style="font-size:11px; color:#94a3b8; padding:6px 0;">
                No misplaced important emails currently found in spam.
            </div>
        `;
        return;
    }

    impContainer.innerHTML = importantSpamEmails.map(eml => `
        <div class="dash-important-row" onclick="openEmailDetailModal('${eml.id}')">
            <div class="item-title">✉ ${escapeHTML(eml.subject)}</div>
            <div class="item-sub">Found in spam · ${escapeHTML(eml.sender)}</div>
        </div>
    `).join("");
}

// --- Inbox ---
function renderInbox() {
    const listEl = document.getElementById("inboxList");
    const countEl = document.getElementById("inboxCountText");
    if (!listEl) return;

    const query = (appState.searchQueries.inbox || "").toLowerCase();
    const inboxEmails = appState.emails.filter(e => e.folder === "inbox");

    const filtered = inboxEmails.filter(e =>
        String(e.sender || "").toLowerCase().includes(query) ||
        String(e.subject || "").toLowerCase().includes(query) ||
        String(e.body || "").toLowerCase().includes(query) ||
        String(e.category || "").toLowerCase().includes(query)
    );

    if (countEl) countEl.textContent = `${filtered.length} email${filtered.length === 1 ? "" : "s"}`;

    if (filtered.length === 0) {
        listEl.innerHTML = `
            <div class="empty-state">
                <i class="fa-regular fa-folder-open empty-state-icon"></i>
                <h4>No emails found</h4>
                <p>${query ? "No emails matched your search query." : "Your inbox is currently clear."}</p>
            </div>
        `;
        return;
    }

    listEl.innerHTML = filtered.map(eml => createEmailCardHTML(eml, "inbox")).join("");
}

// --- Spam ---
function renderSpam() {
    const listEl = document.getElementById("spamList");
    const countEl = document.getElementById("spamCountText");
    const banner = document.getElementById("repeatedSpamGlobalBanner");
    const bannerText = document.getElementById("repeatedSpamBannerText");
    if (!listEl) return;

    const spamEmails = appState.emails.filter(e => e.folder === "spam");
    const query = (appState.searchQueries.spam || "").toLowerCase();

    const filtered = spamEmails.filter(e =>
        String(e.sender || "").toLowerCase().includes(query) ||
        String(e.subject || "").toLowerCase().includes(query) ||
        String(e.body || "").toLowerCase().includes(query) ||
        String(e.category || "").toLowerCase().includes(query)
    );

    if (countEl) countEl.textContent = `${filtered.length} spam email${filtered.length === 1 ? "" : "s"}`;

    // Check for any repeated spam senders in Spam (>= 3 spam emails)
    const sendersMap = {};
    spamEmails.forEach(e => {
        const s = extractEmailAddress(e.sender).toLowerCase();
        sendersMap[s] = (sendersMap[s] || 0) + 1;
    });
    const repeatedSenders = Object.keys(sendersMap).filter(s => sendersMap[s] >= 3);

    if (banner) {
        if (repeatedSenders.length > 0) {
            banner.classList.remove("hidden");
            if (bannerText) {
                bannerText.textContent = `Repeated unwanted sender detected: ${repeatedSenders.join(", ")} (sent 3+ unwanted emails).`;
            }
        } else {
            banner.classList.add("hidden");
        }
    }

    if (filtered.length === 0) {
        listEl.innerHTML = `
            <div class="empty-state">
                <i class="fa-solid fa-shield-check empty-state-icon"></i>
                <h4>No spam emails</h4>
                <p>${query ? "No spam emails match your search." : "No unwanted emails detected in your spam folder."}</p>
            </div>
        `;
        return;
    }

    listEl.innerHTML = filtered.map(eml => createEmailCardHTML(eml, "spam")).join("");
}

// --- Threats ---
function renderThreats() {
    const listEl = document.getElementById("threatList");
    const totalEl = document.getElementById("threatSummaryTotal");
    const highEl = document.getElementById("threatCountHigh");
    const medEl = document.getElementById("threatCountMed");
    const lowEl = document.getElementById("threatCountLow");
    if (!listEl) return;

    const threats = getAllThreats();
    const query = (appState.searchQueries.threats || "").toLowerCase();

    const filtered = threats.filter(e =>
        String(e.sender || "").toLowerCase().includes(query) ||
        String(e.subject || "").toLowerCase().includes(query) ||
        String(e.body || "").toLowerCase().includes(query) ||
        (Array.isArray(e.reasons) && e.reasons.some(r => String(r).toLowerCase().includes(query)))
    );

    // Calculate High (>=70), Medium (45-69), Low (<45)
    let high = 0, med = 0, low = 0;
    threats.forEach(t => {
        if (t.score >= 70) high++;
        else if (t.score >= 45) med++;
        else low++;
    });

    if (totalEl) totalEl.textContent = `${threats.length} Threats Detected`;
    if (highEl) highEl.textContent = `${high} High`;
    if (medEl) medEl.textContent = `${med} Medium`;
    if (lowEl) lowEl.textContent = `${low} Low`;

    if (filtered.length === 0) {
        listEl.innerHTML = `
            <div class="empty-state">
                <i class="fa-solid fa-shield-halved empty-state-icon"></i>
                <h4>No threats detected</h4>
                <p>${query ? "No threats matched your search." : "No suspicious or harmful emails found in system."}</p>
            </div>
        `;
        return;
    }

    listEl.innerHTML = filtered.map(t => {
        let riskClass = "risk-low";
        let riskBadge = "Low Risk";
        if (t.score >= 70) {
            riskClass = "risk-high";
            riskBadge = "High Risk";
        } else if (t.score >= 45) {
            riskClass = "risk-medium";
            riskBadge = "Medium Risk";
        }

        const reasonsHtml = (t.reasons || ["Suspicious pattern detected"])
            .slice(0, 2)
            .map(r => `<div><i class="fa-solid fa-circle-exclamation"></i> ${escapeHTML(r)}</div>`)
            .join("");

        return `
            <div class="threat-card-item ${riskClass}" onclick="openThreatResultForEmail('${t.id}')">
                <div class="threat-top-row">
                    <span class="threat-title-text">${escapeHTML(t.subject)}</span>
                    <span class="threat-score-pill">${t.score}/100</span>
                </div>
                <small style="color:#cbd5e1; font-size:11px;">${escapeHTML(t.sender)}</small>
                <div style="margin-top:4px; font-size:11px; font-weight:600; color:#ffffff;">
                    ${riskBadge} – ${t.score}/100
                </div>
                <div class="threat-reasons-preview">
                    ${reasonsHtml}
                </div>
            </div>
        `;
    }).join("");
}

// --- Important Emails ---
function renderImportant() {
    const listEl = document.getElementById("importantList");
    const noticeEl = document.getElementById("importantFoundInSpamNotice");
    if (!listEl) return;

    const importantSpamEmails = getImportantEmailsInSpam();
    const query = (appState.searchQueries.important || "").toLowerCase();

    if (noticeEl) {
        noticeEl.textContent = `${importantSpamEmails.length} important email${importantSpamEmails.length === 1 ? "" : "s"} found in Spam`;
    }

    // All important emails across folders
    const allImportant = appState.emails.filter(e => isEmailImportant(e));

    const filtered = allImportant.filter(e =>
        String(e.sender || "").toLowerCase().includes(query) ||
        String(e.subject || "").toLowerCase().includes(query) ||
        String(e.body || "").toLowerCase().includes(query)
    );

    if (filtered.length === 0) {
        listEl.innerHTML = `
            <div class="empty-state">
                <i class="fa-regular fa-star empty-state-icon"></i>
                <h4>No important emails</h4>
                <p>${query ? "No important emails match your query." : "No priority academic or project notices detected."}</p>
            </div>
        `;
        return;
    }

    listEl.innerHTML = filtered.map(eml => createEmailCardHTML(eml, "important")).join("");
}

// --- Reports ---
function renderReports() {
    const repAnalysed = document.getElementById("reportAnalysed");
    const repThreats = document.getElementById("reportThreats");
    const repSpam = document.getElementById("reportSpam");
    const repImportant = document.getElementById("reportImportant");
    const repBlocked = document.getElementById("reportBlockedSenders");
    const repPosture = document.getElementById("reportPosture");

    const threats = getAllThreats();
    const spam = appState.emails.filter(e => e.folder === "spam");
    const important = appState.emails.filter(e => isEmailImportant(e));

    const threatCountVal = Math.max(threats.length, appState.stats.threats);
    const spamCountVal = Math.max(spam.length, appState.stats.spam);
    const importantCountVal = Math.max(important.length, appState.stats.important);

    if (repAnalysed) repAnalysed.textContent = appState.stats.analysed;
    if (repThreats) repThreats.textContent = threatCountVal;
    if (repSpam) repSpam.textContent = spamCountVal;
    if (repImportant) repImportant.textContent = importantCountVal;
    if (repBlocked) repBlocked.textContent = appState.blockedSenders.length;

    if (repPosture) {
        if (threatCountVal > 15) {
            repPosture.textContent = "Elevated Risk";
            repPosture.className = "posture-danger";
            repPosture.style.color = "#ef4444";
        } else {
            repPosture.textContent = "Protected";
            repPosture.className = "posture-good";
            repPosture.style.color = "#10b981";
        }
    }

    // Update risk composite bar
    const total = Math.max(1, appState.emails.length);
    let safeCount = 0, spamCount = 0, suspCount = 0, harmCount = 0;
    appState.emails.forEach(e => {
        if (e.category === "Harmful") harmCount++;
        else if (e.category === "Suspicious") suspCount++;
        else if (e.category === "Spam") spamCount++;
        else safeCount++;
    });

    const pSafe = Math.round((safeCount / total) * 100);
    const pSpam = Math.round((spamCount / total) * 100);
    const pSusp = Math.round((suspCount / total) * 100);
    const pHarm = Math.max(0, 100 - (pSafe + pSpam + pSusp));

    const bSafe = document.getElementById("barSliceSafe");
    const bSpam = document.getElementById("barSliceSpam");
    const bSusp = document.getElementById("barSliceSusp");
    const bHarm = document.getElementById("barSliceHarm");

    if (bSafe) bSafe.style.width = `${pSafe}%`;
    if (bSpam) bSpam.style.width = `${pSpam}%`;
    if (bSusp) bSusp.style.width = `${pSusp}%`;
    if (bHarm) bHarm.style.width = `${pHarm}%`;
}


/* =========================================================
   9. EMAIL CARD HTML BUILDER
========================================================= */

function createEmailCardHTML(email, context = "inbox") {
    const isRepeated = isRepeatedSpammer(email.sender);
    const inSpam = email.folder === "spam";
    const importantTag = isEmailImportant(email);

    let categoryClass = "badge-safe";
    if (email.category === "Harmful") categoryClass = "badge-harmful";
    else if (email.category === "Suspicious") categoryClass = "badge-suspicious";
    else if (email.category === "Spam") categoryClass = "badge-spam";

    // Actions depending on context
    let actionButtons = "";

    if (context === "spam") {
        actionButtons = `
            <button class="action-icon-btn btn-success" onclick="event.stopPropagation(); moveToInbox('${email.id}')" title="Move to Inbox">
                <i class="fa-solid fa-inbox"></i> Move to Inbox
            </button>
            <button class="action-icon-btn" onclick="event.stopPropagation(); markSafe('${email.id}')" title="Mark Safe">
                <i class="fa-solid fa-circle-check"></i> Mark Safe
            </button>
            <button class="action-icon-btn btn-danger" onclick="event.stopPropagation(); blockSender('${escapeHTML(email.sender)}')" title="Block Sender">
                <i class="fa-solid fa-user-slash"></i> Block
            </button>
            <button class="action-icon-btn btn-danger" onclick="event.stopPropagation(); deleteEmail('${email.id}')" title="Delete Email">
                <i class="fa-solid fa-trash"></i> Delete
            </button>
        `;
    } else if (context === "important") {
        actionButtons = `
            ${inSpam ? `
                <button class="action-icon-btn btn-success" onclick="event.stopPropagation(); moveToInbox('${email.id}')" title="Move to Inbox">
                    <i class="fa-solid fa-inbox"></i> Move to Inbox
                </button>
            ` : ""}
            <button class="action-icon-btn" onclick="event.stopPropagation(); markImportant('${email.id}')" title="Mark Important">
                <i class="fa-solid fa-star"></i> Important
            </button>
            <button class="action-icon-btn btn-danger" onclick="event.stopPropagation(); deleteEmail('${email.id}')" title="Delete">
                <i class="fa-solid fa-trash"></i>
            </button>
        `;
    } else {
        // Inbox
        actionButtons = `
            <button class="action-icon-btn" onclick="event.stopPropagation(); moveToSpam('${email.id}')" title="Report as Spam">
                <i class="fa-solid fa-ban"></i> Spam
            </button>
            <button class="action-icon-btn" onclick="event.stopPropagation(); markImportant('${email.id}')" title="Toggle Important">
                <i class="fa-solid fa-star"></i>
            </button>
            <button class="action-icon-btn btn-danger" onclick="event.stopPropagation(); deleteEmail('${email.id}')" title="Delete Email">
                <i class="fa-solid fa-trash"></i>
            </button>
        `;
    }

    return `
        <div class="email-card-item" onclick="openEmailDetailModal('${email.id}')">
            <div class="email-header-row">
                <div class="email-title-text">
                    <i class="fa-regular fa-envelope"></i>
                    <span>${escapeHTML(email.subject)}</span>
                </div>
                <span class="email-date-text">${escapeHTML(email.date)}</span>
            </div>

            <div class="email-sender-text">${escapeHTML(email.sender)}</div>

            <p class="email-preview-text">${escapeHTML(email.body || "")}</p>

            <div class="email-footer-row">
                <div class="email-tags-group">
                    <span class="status-badge ${categoryClass}">${email.category}</span>
                    ${importantTag ? `<span class="status-badge badge-important-tag">☆ Important${inSpam ? " · Found in Spam" : ""}</span>` : ""}
                    ${isRepeated ? `<span class="status-badge badge-repeated-spam">⚠ Repeated unwanted sender</span>` : ""}
                </div>

                <div class="email-actions-toolbar">
                    ${actionButtons}
                </div>
            </div>
        </div>
    `;
}


/* =========================================================
   10. THREAT RESULT VIEW & ACTIONS
========================================================= */

function renderThreatResultView(result) {
    const card = document.getElementById("threatResultCard");
    const headingText = document.getElementById("resultHeadingText");
    const descText = document.getElementById("resultDescription");
    const badge = document.getElementById("resultRiskLevelBadge");
    const scoreVal = document.getElementById("resultRiskScoreValue");
    const senderEl = document.getElementById("resultSenderText");
    const subjEl = document.getElementById("resultSubjectText");
    const catEl = document.getElementById("resultCategoryText");
    const reasonsList = document.getElementById("resultReasonsList");

    if (!card) return;

    // Remove old theme classes
    card.classList.remove("theme-safe", "theme-spam", "theme-suspicious", "theme-harmful");

    const cat = result.category || "Safe";
    card.classList.add(`theme-${cat.toLowerCase()}`);

    if (headingText) {
        headingText.textContent = `${cat} Email`;
    }

    if (descText) {
        if (cat === "Safe") descText.textContent = "This email appears safe and legitimate.";
        else if (cat === "Spam") descText.textContent = "This email appears to be unwanted promotional material.";
        else if (cat === "Suspicious") descText.textContent = "This email may be unsafe. Exercise caution.";
        else descText.textContent = "This email contains severe malicious threat indicators!";
    }

    let riskLevelText = "LOW RISK";
    if (result.score >= 81) riskLevelText = "CRITICAL RISK";
    else if (result.score >= 61) riskLevelText = "HIGH RISK";
    else if (result.score >= 31) riskLevelText = "MEDIUM RISK";

    if (badge) badge.textContent = riskLevelText;
    if (scoreVal) scoreVal.textContent = `${result.score}/100`;
    if (senderEl) senderEl.textContent = result.sender || "unknown.sender@gmail.com";
    if (subjEl) subjEl.textContent = result.subject || "Email Analysis";
    if (catEl) {
        catEl.textContent = cat.toUpperCase();
        catEl.className = `category-tag badge-${cat.toLowerCase()}`;
    }

    // Reasons icons map
    const icons = [
        "fa-solid fa-link",
        "fa-solid fa-user-xmark",
        "fa-solid fa-triangle-exclamation",
        "fa-solid fa-credit-card",
        "fa-solid fa-envelope-open-text",
        "fa-solid fa-shield-virus"
    ];

    if (reasonsList) {
        reasonsList.innerHTML = (result.reasons || ["No critical threats detected"]).map((r, i) => `
            <div class="reason-pill-item">
                <i class="${icons[i % icons.length]}"></i>
                <span>${escapeHTML(r)}</span>
            </div>
        `).join("");
    }
}

/**
 * Handles actions initiated from the Threat Result Page.
 */
function actionFromThreatResult(actionType) {
    const res = appState.activeAnalysisResult;
    if (!res) {
        showToast("No active analyzed email found.", "error");
        return;
    }

    // Look for existing email in state or create one
    let targetEmail = appState.emails.find(e => e.id === res.id);

    if (!targetEmail) {
        targetEmail = {
            id: res.id || `eml-${Date.now()}`,
            sender: res.sender || "unknown.sender@gmail.com",
            subject: res.subject || "Analyzed Email",
            body: res.body || "No email body text provided.",
            folder: res.score >= 31 ? "spam" : "inbox",
            category: res.category,
            score: res.score,
            reasons: res.reasons,
            isImportant: isEmailImportant(res),
            date: "Today",
            timestamp: Date.now(),
            flaggedInSpam: false
        };
        appState.emails.unshift(targetEmail);
    }

    switch (actionType) {
        case "reportSpam":
            moveToSpam(targetEmail.id);
            res.category = "Spam";
            res.score = Math.max(res.score, 45);
            renderThreatResultView(res);
            break;
        case "blockSender":
            blockSender(targetEmail.sender);
            moveToSpam(targetEmail.id);
            res.category = "Harmful";
            renderThreatResultView(res);
            break;
        case "deleteEmail":
            deleteEmail(targetEmail.id);
            showPage("inbox");
            break;
        case "moveToInbox":
            moveToInbox(targetEmail.id);
            renderThreatResultView(res);
            break;
        case "markSafe":
            markSafe(targetEmail.id);
            res.category = "Safe";
            res.score = 10;
            res.reasons = ["Manually certified safe by user action"];
            renderThreatResultView(res);
            break;
    }
}

function openThreatResultForEmail(emailId) {
    const email = appState.emails.find(e => e.id === emailId);
    if (!email) return;

    appState.activeAnalysisResult = {
        id: email.id,
        sender: email.sender,
        subject: email.subject,
        body: email.body,
        score: email.score,
        category: email.category,
        reasons: email.reasons
    };

    showPage("threatResult");
}


/* =========================================================
   11. EMAIL ANALYSIS INGESTION & TRIGGER
========================================================= */

function triggerEmailAnalysis() {
    const textarea = document.getElementById("emailContent");
    const rawContent = textarea ? textarea.value.trim() : "";

    if (!rawContent) {
        showToast("Please upload an email file or paste email content first.", "error");
        return;
    }

    const btn = document.getElementById("runAnalysisBtn");
    const loader = document.getElementById("analysisLoadingIndicator");
    const loaderText = document.getElementById("analysisLoadingText");
    const progressBar = document.getElementById("analysisProgressBar");

    if (btn) btn.disabled = true;
    if (loader) loader.classList.remove("hidden");

    // Stepped animated loading sequence
    const steps = [
        { progress: 25, text: "Scanning headers & sender reputation..." },
        { progress: 55, text: "Inspecting embedded hyperlinks & domain safety..." },
        { progress: 85, text: "Running heuristic keyword & urgency analysis..." },
        { progress: 100, text: "Finalizing threat score & mitigation status..." }
    ];

    let currentStep = 0;
    const interval = setInterval(() => {
        if (currentStep < steps.length) {
            const step = steps[currentStep];
            if (progressBar) progressBar.style.width = `${step.progress}%`;
            if (loaderText) loaderText.textContent = step.text;
            currentStep++;
        } else {
            clearInterval(interval);
            setTimeout(() => {
                finalizeAnalysis(rawContent);
                if (btn) btn.disabled = false;
                if (loader) loader.classList.add("hidden");
                if (progressBar) progressBar.style.width = "0%";
            }, 300);
        }
    }, 280);
}

function finalizeAnalysis(rawContent) {
    const parsed = parseRawEmailHeaders(rawContent);
    const evaluation = calculateThreatScore(parsed.body, parsed.sender, parsed.subject);

    const isThreatItem = evaluation.score >= 31 && evaluation.category !== "Safe";

    const newEmail = {
        id: `eml-analysed-${Date.now()}`,
        sender: parsed.sender,
        subject: parsed.subject,
        body: parsed.body,
        folder: evaluation.category === "Safe" ? "inbox" : "spam",
        category: evaluation.category,
        score: evaluation.score,
        isThreat: isThreatItem,
        reasons: evaluation.reasons,
        isImportant: isEmailImportant({ subject: parsed.subject, body: parsed.body }),
        date: "Just now",
        timestamp: Date.now(),
        flaggedInSpam: evaluation.category !== "Safe"
    };

    // Store in state & update dynamic stats
    appState.emails.unshift(newEmail);
    appState.stats.analysed++;
    if (isThreatItem) appState.stats.threats++;
    if (evaluation.category === "Spam") appState.stats.spam++;
    if (newEmail.isImportant) appState.stats.important++;

    appState.activeAnalysisResult = newEmail;

    addNotification(`Analyzed email from ${parsed.sender} – Classified as ${evaluation.category} (${evaluation.score}/100)`);
    saveToStorage();
    updateAllStatsAndBadges();

    showPage("threatResult");
    showToast(`Email analyzed: ${evaluation.category} (${evaluation.score}/100)`, "success");
}

function handleFileUpload(event) {
    const file = event.target.files && event.target.files[0];
    if (!file) return;

    const validExtensions = /\.(eml|txt|msg)$/i;
    if (!validExtensions.test(file.name)) {
        showToast("Please select a .eml, .txt, or .msg email file.", "error");
        event.target.value = "";
        return;
    }

    const reader = new FileReader();
    reader.onload = function(e) {
        const content = e.target.result || "";
        const textarea = document.getElementById("emailContent");
        const filenameTag = document.getElementById("uploadedFileName");

        if (textarea) textarea.value = content;
        if (filenameTag) {
            filenameTag.textContent = file.name;
            filenameTag.classList.remove("hidden");
        }
        showToast(`${file.name} loaded successfully.`, "success");
    };

    reader.onerror = function() {
        showToast("Error reading file.", "error");
    };

    reader.readAsText(file);
}

function loadSampleEmail(type) {
    const textarea = document.getElementById("emailContent");
    if (!textarea) return;

    const samples = {
        phishing: "From: support@secure-paypal-verify.com\nSubject: Urgent: Account Suspended within 24 Hours\n\nDear Customer,\n\nYour account has been temporarily suspended due to multiple unauthorized login attempts. Click here to confirm your password and billing info immediately:\nhttp://bit.ly/paypal-auth-verify-portal\n\nFailure to verify will lead to permanent termination.",
        spam: "From: promo@megadeals.com\nSubject: Congratulations! Claim your $500 Gift Card Voucher\n\nWinner! You were randomly chosen in our seasonal lottery draw to receive a complimentary luxury prize voucher. Click here to claim your cash reward now!",
        internship: "From: placement@college.edu\nSubject: College Internship & Project Verification Update\n\nDear Student,\n\nYour internship selection list for the upcoming campus placement drive is ready for faculty verification. Please review the project submission requirements before tomorrow's meeting.",
        safe: "From: team@projectmail.com\nSubject: Sprint Retrospective and Code Review\n\nHi everyone,\n\nOur weekly project sync is scheduled for tomorrow at 3:00 PM. Please push your git commits and verify the unit tests before we meet.\n\nBest,\nDev Lead"
    };

    textarea.value = samples[type] || "";
    showToast(`Loaded ${type} sample email.`, "success");
}


/* =========================================================
   12. EMAIL ACTION WORKFLOWS
========================================================= */

function moveToSpam(emailId) {
    const eml = appState.emails.find(e => e.id === emailId);
    if (!eml) return;

    if (eml.folder !== "spam") {
        eml.folder = "spam";
        appState.stats.spam++;
        saveToStorage();
        updateAllStatsAndBadges();
        renderCurrentPage();

        addNotification(`Moved email "${eml.subject}" to Spam.`);
        showToast("Email moved to Spam.");
    }
}

function moveToInbox(emailId) {
    const eml = appState.emails.find(e => e.id === emailId);
    if (!eml) return;

    if (eml.folder === "spam") {
        eml.folder = "inbox";
        eml.flaggedInSpam = false;
        appState.stats.spam = Math.max(0, appState.stats.spam - 1);
        saveToStorage();
        updateAllStatsAndBadges();
        renderCurrentPage();

        addNotification(`Moved email "${eml.subject}" to Inbox.`);
        showToast("Email moved to Inbox.", "success");
    }
}

function deleteEmail(emailId) {
    if (!confirm("Are you sure you want to delete this email permanently?")) return;

    const idx = appState.emails.findIndex(e => e.id === emailId);
    if (idx !== -1) {
        const deleted = appState.emails.splice(idx, 1)[0];
        if (deleted.folder === "spam") {
            appState.stats.spam = Math.max(0, appState.stats.spam - 1);
        }
        if (deleted.isThreat || deleted.category === "Harmful" || deleted.category === "Suspicious") {
            appState.stats.threats = Math.max(0, appState.stats.threats - 1);
        }
        if (deleted.isImportant) {
            appState.stats.important = Math.max(0, appState.stats.important - 1);
        }

        saveToStorage();
        updateAllStatsAndBadges();
        renderCurrentPage();
        closeEmailModal();

        addNotification(`Deleted email "${deleted.subject}".`);
        showToast("Email deleted successfully.");

        if (appState.currentPage === "threatResult") {
            showPage("inbox");
        }
    }
}

function blockSender(senderEmail) {
    if (!senderEmail) return;
    const clean = extractEmailAddress(senderEmail).trim();

    if (appState.blockedSenders.includes(clean)) {
        showToast("Sender is already in the blocked list.");
        return;
    }

    appState.blockedSenders.push(clean);

    // Auto-move existing emails from sender to spam
    appState.emails.forEach(e => {
        const addr = extractEmailAddress(e.sender).toLowerCase();
        if (addr === clean.toLowerCase()) {
            if (e.folder !== "spam") {
                e.folder = "spam";
                appState.stats.spam++;
            }
            e.score = Math.max(e.score, 75);
            e.category = "Suspicious";
            e.isThreat = true;
            if (!e.reasons.includes("Sender blocked by security policy")) {
                e.reasons.unshift("Sender blocked by security policy");
            }
        }
    });

    saveToStorage();
    updateAllStatsAndBadges();
    renderCurrentPage();
    renderBlockedSendersList();

    addNotification(`Blocked sender: ${clean}`);
    showToast(`Sender blocked: ${clean}`, "success");
}

function unblockSender(senderEmail) {
    appState.blockedSenders = appState.blockedSenders.filter(s => s !== senderEmail);
    saveToStorage();
    renderBlockedSendersList();
    showToast(`Unblocked ${senderEmail}`);
}

function markSafe(emailId) {
    const eml = appState.emails.find(e => e.id === emailId);
    if (!eml) return;

    const wasThreat = eml.isThreat || eml.category === "Suspicious" || eml.category === "Harmful";
    const wasSpam = eml.folder === "spam";

    eml.category = "Safe";
    eml.score = Math.min(eml.score, 12);
    eml.folder = "inbox";
    eml.isThreat = false;
    eml.reasons = ["Manually certified safe by user action"];
    eml.flaggedInSpam = false;

    if (wasThreat) {
        appState.stats.threats = Math.max(0, appState.stats.threats - 1);
    }
    if (wasSpam) {
        appState.stats.spam = Math.max(0, appState.stats.spam - 1);
    }

    saveToStorage();
    updateAllStatsAndBadges();
    renderCurrentPage();

    addNotification(`Certified email "${eml.subject}" as Safe.`);
    showToast("Email marked as safe and moved to Inbox.", "success");
}

function markImportant(emailId) {
    const eml = appState.emails.find(e => e.id === emailId);
    if (!eml) return;

    eml.isImportant = !eml.isImportant;
    if (eml.isImportant) {
        appState.stats.important++;
    } else {
        appState.stats.important = Math.max(0, appState.stats.important - 1);
    }

    saveToStorage();
    updateAllStatsAndBadges();
    renderCurrentPage();

    showToast(eml.isImportant ? "Email marked as important." : "Removed important status.");
}


/* =========================================================
   13. SEARCH HANDLER
========================================================= */

function handleSearch(section, value) {
    appState.searchQueries[section] = value;
    switch (section) {
        case "inbox": renderInbox(); break;
        case "spam": renderSpam(); break;
        case "threats": renderThreats(); break;
        case "important": renderImportant(); break;
    }
}

function clearSearch(section) {
    appState.searchQueries[section] = "";
    const input = document.getElementById(`${section}SearchInput`);
    if (input) input.value = "";
    handleSearch(section, "");
}


/* =========================================================
   14. STATS & BADGES UPDATE
========================================================= */

function updateAllStatsAndBadges() {
    const threats = getAllThreats();
    const spam = appState.emails.filter(e => e.folder === "spam");
    const inbox = appState.emails.filter(e => e.folder === "inbox");
    const important = appState.emails.filter(e => isEmailImportant(e));

    // Calculate dynamic stats keeping the baseline synchronized
    const statsThreatCount = Math.max(threats.length, appState.stats.threats);
    const statsSpamCount = Math.max(spam.length, appState.stats.spam);
    const statsImportantCount = Math.max(important.length, appState.stats.important);

    // Dashboard Cards
    const elAnalysed = document.getElementById("analysedCount");
    const elThreats = document.getElementById("threatCount");
    const elSpam = document.getElementById("spamCount");
    const elImportant = document.getElementById("importantCount");

    if (elAnalysed) elAnalysed.textContent = appState.stats.analysed;
    if (elThreats) elThreats.textContent = statsThreatCount;
    if (elSpam) elSpam.textContent = statsSpamCount;
    if (elImportant) elImportant.textContent = statsImportantCount;

    // Sidebar Nav Badges
    const bInbox = document.getElementById("badgeInbox");
    const bThreats = document.getElementById("badgeThreats");
    const bSpam = document.getElementById("badgeSpam");
    const bImportant = document.getElementById("badgeImportant");

    if (bInbox) bInbox.textContent = inbox.length;
    if (bThreats) bThreats.textContent = threats.length;
    if (bSpam) bSpam.textContent = spam.length;
    if (bImportant) bImportant.textContent = important.length;

    // Notification Dot
    const dot = document.getElementById("notifDot");
    if (dot) {
        dot.style.display = appState.notifications.length > 0 ? "block" : "none";
    }
}


/* =========================================================
   15. MODAL SYSTEM (EMAIL DETAILS, SETTINGS, PROFILE)
========================================================= */

function openEmailDetailModal(emailId) {
    const eml = appState.emails.find(e => e.id === emailId);
    if (!eml) return;

    const modal = document.getElementById("emailDetailModal");
    const subjEl = document.getElementById("modalSubject");
    const fromEl = document.getElementById("modalFrom");
    const dateEl = document.getElementById("modalDate");
    const folderEl = document.getElementById("modalFolder");
    const scoreEl = document.getElementById("modalScore");
    const badgeEl = document.getElementById("modalCategoryBadge");
    const reasonsList = document.getElementById("modalReasonsList");
    const bodyEl = document.getElementById("modalBodyText");
    const repeatedAlert = document.getElementById("modalRepeatedSpamAlert");
    const actionsToolbar = document.getElementById("modalActionsToolbar");

    if (!modal) return;

    if (subjEl) subjEl.textContent = eml.subject;
    if (fromEl) fromEl.textContent = eml.sender;
    if (dateEl) dateEl.textContent = eml.date;
    if (folderEl) folderEl.textContent = eml.folder.toUpperCase();

    if (scoreEl) {
        scoreEl.textContent = `${eml.score} / 100`;
        scoreEl.style.color = eml.score >= 61 ? "#ef4444" : (eml.score >= 31 ? "#f59e0b" : "#10b981");
    }

    if (badgeEl) {
        badgeEl.textContent = eml.category.toUpperCase();
        badgeEl.className = `category-badge badge-${eml.category.toLowerCase()}`;
    }

    if (repeatedAlert) {
        if (isRepeatedSpammer(eml.sender)) {
            repeatedAlert.classList.remove("hidden");
        } else {
            repeatedAlert.classList.add("hidden");
        }
    }

    if (reasonsList) {
        reasonsList.innerHTML = (eml.reasons || ["Standard email"]).map(r => `
            <li><i class="fa-solid fa-shield-halved"></i> ${escapeHTML(r)}</li>
        `).join("");
    }

    if (bodyEl) bodyEl.textContent = eml.body || "No email body content.";

    if (actionsToolbar) {
        const inSpam = eml.folder === "spam";
        actionsToolbar.innerHTML = `
            ${inSpam ? `
                <button class="action-icon-btn btn-success" onclick="moveToInbox('${eml.id}'); closeEmailModal();">
                    <i class="fa-solid fa-inbox"></i> Move to Inbox
                </button>
            ` : `
                <button class="action-icon-btn" onclick="moveToSpam('${eml.id}'); closeEmailModal();">
                    <i class="fa-solid fa-ban"></i> Report Spam
                </button>
            `}
            <button class="action-icon-btn" onclick="markSafe('${eml.id}'); closeEmailModal();">
                <i class="fa-solid fa-circle-check"></i> Mark Safe
            </button>
            <button class="action-icon-btn" onclick="markImportant('${eml.id}'); closeEmailModal();">
                <i class="fa-solid fa-star"></i> Toggle Important
            </button>
            <button class="action-icon-btn btn-danger" onclick="blockSender('${escapeHTML(eml.sender)}'); closeEmailModal();">
                <i class="fa-solid fa-user-slash"></i> Block Sender
            </button>
            <button class="action-icon-btn btn-danger" onclick="deleteEmail('${eml.id}'); closeEmailModal();">
                <i class="fa-solid fa-trash"></i> Delete
            </button>
        `;
    }

    modal.classList.remove("hidden");
}

function closeEmailModal() {
    const modal = document.getElementById("emailDetailModal");
    if (modal) modal.classList.add("hidden");
}

function openSettingsModal() {
    renderBlockedSendersList();
    const modal = document.getElementById("settingsModal");
    if (modal) modal.classList.remove("hidden");
}

function closeSettingsModal() {
    const modal = document.getElementById("settingsModal");
    if (modal) modal.classList.add("hidden");
}

function renderBlockedSendersList() {
    const container = document.getElementById("blockedSendersList");
    if (!container) return;

    if (appState.blockedSenders.length === 0) {
        container.innerHTML = `
            <div style="font-size:11px; color:#94a3b8; padding:8px 0;">
                No senders currently blocked.
            </div>
        `;
        return;
    }

    container.innerHTML = appState.blockedSenders.map(sender => `
        <div class="blocked-item">
            <span><i class="fa-solid fa-ban"></i> ${escapeHTML(sender)}</span>
            <button class="unblock-btn" onclick="unblockSender('${escapeHTML(sender)}')">
                Unblock
            </button>
        </div>
    `).join("");
}

function openProfileModal() {
    const modal = document.getElementById("profileModal");
    if (modal) modal.classList.remove("hidden");
}

function closeProfileModal() {
    const modal = document.getElementById("profileModal");
    if (modal) modal.classList.add("hidden");
}

function saveUserSettings() {
    const agg = document.getElementById("settingAggressiveLinks");
    const rec = document.getElementById("settingKeywordRecovery");

    if (agg) appState.settings.aggressiveLinks = agg.checked;
    if (rec) appState.settings.keywordRecovery = rec.checked;

    saveToStorage();
    showToast("Settings saved.");
}


/* =========================================================
   16. NOTIFICATIONS & TOAST SYSTEM
========================================================= */

function addNotification(text) {
    const notif = {
        id: Date.now(),
        text: text,
        time: "Just now"
    };
    appState.notifications.unshift(notif);
    if (appState.notifications.length > 20) {
        appState.notifications.pop();
    }
    renderNotificationsDropdown();
    updateAllStatsAndBadges();
}

function toggleNotificationDropdown() {
    const drop = document.getElementById("notificationDropdown");
    if (!drop) return;

    drop.classList.toggle("hidden");
    if (!drop.classList.contains("hidden")) {
        renderNotificationsDropdown();
    }
}

function renderNotificationsDropdown() {
    const listEl = document.getElementById("notificationList");
    if (!listEl) return;

    if (appState.notifications.length === 0) {
        listEl.innerHTML = `
            <div style="padding:14px; text-align:center; font-size:11px; color:#94a3b8;">
                No security alerts.
            </div>
        `;
        return;
    }

    listEl.innerHTML = appState.notifications.map(n => `
        <div class="notif-item">
            <span>${escapeHTML(n.text)}</span>
            <span class="notif-time">${n.time}</span>
        </div>
    `).join("");
}

function clearNotifications() {
    appState.notifications = [];
    renderNotificationsDropdown();
    updateAllStatsAndBadges();
    showToast("Notifications cleared.");
}

function showToast(message, type = "normal") {
    let toast = document.getElementById("toast");
    if (!toast) return;

    toast.textContent = message;
    toast.className = "toast-notification show";

    if (type === "error") {
        toast.classList.add("toast-error");
    } else if (type === "success") {
        toast.classList.add("toast-success");
    }

    clearTimeout(window.toastTimer);
    window.toastTimer = setTimeout(() => {
        toast.classList.remove("show");
    }, 2500);
}


/* =========================================================
   17. LOGIN & AUTHENTICATION (PROTOTYPE)
========================================================= */

function handleLoginSubmit(event) {
    if (event) event.preventDefault();

    const usernameInput = document.getElementById("username");
    const passwordInput = document.getElementById("password");
    const validationEl = document.getElementById("loginValidationMsg");

    const username = usernameInput ? usernameInput.value.trim() : "";
    const password = passwordInput ? passwordInput.value.trim() : "";

    if (!username || !password) {
        if (validationEl) {
            validationEl.textContent = "Please enter both your email and password.";
            validationEl.classList.remove("hidden");
        }
        showToast("Please enter username and password.", "error");
        return;
    }

    if (!username.includes("@")) {
        if (validationEl) {
            validationEl.textContent = "Please provide a valid email format.";
            validationEl.classList.remove("hidden");
        }
        showToast("Invalid email address.", "error");
        return;
    }

    if (validationEl) validationEl.classList.add("hidden");

    // Successful login transition
    document.getElementById("loginPage").classList.add("hidden");
    document.getElementById("app").classList.remove("hidden");

    showPage("dashboard");
    showToast("Welcome to Thadam Labs Security Portal", "success");
}

function logoutUser() {
    document.getElementById("app").classList.add("hidden");
    document.getElementById("loginPage").classList.remove("hidden");

    const passwordInput = document.getElementById("password");
    if (passwordInput) passwordInput.value = "";

    showToast("You have been signed out.");
}

function togglePassword() {
    const pwd = document.getElementById("password");
    const eyeBtn = document.getElementById("passwordEyeBtn");
    if (!pwd) return;

    if (pwd.type === "password") {
        pwd.type = "text";
        if (eyeBtn) eyeBtn.innerHTML = `<i class="fa-regular fa-eye-slash"></i>`;
    } else {
        pwd.type = "password";
        if (eyeBtn) eyeBtn.innerHTML = `<i class="fa-regular fa-eye"></i>`;
    }
}

function forgotPassword(event) {
    if (event) event.preventDefault();
    showToast("Password reset link dispatched to authorized administrator email.");
}

function createAccount(event) {
    if (event) event.preventDefault();
    showToast("Enterprise registration portal available for SOC tiers.");
}

function showLoginAbout() {
    showToast("Thadam Labs: Real-time heuristic AI email threat detection suite.");
}

function showLoginFeatures() {
    showToast("Features: Phishing heuristic analysis, spam recovery, repeated spam detection.");
}


/* =========================================================
   18. MOBILE SIDEBAR & RESPONSIVENESS
========================================================= */

function toggleSidebar(forceState) {
    const sidebar = document.getElementById("sidebar");
    const backdrop = document.getElementById("sidebarBackdrop");
    if (!sidebar) return;

    if (typeof forceState === "boolean") {
        if (forceState) {
            sidebar.classList.add("open");
            if (backdrop) backdrop.classList.add("active");
        } else {
            sidebar.classList.remove("open");
            if (backdrop) backdrop.classList.remove("active");
        }
    } else {
        sidebar.classList.toggle("open");
        if (backdrop) backdrop.classList.toggle("active", sidebar.classList.contains("open"));
    }
}


/* =========================================================
   19. REPORTS GENERATOR
========================================================= */

function generateSecurityReport() {
    renderReports();
    showToast("Security report re-generated & synchronized with threat database.", "success");
}


/* =========================================================
   20. KEYBOARD SHORTCUTS & GLOBAL CLICK HANDLERS
========================================================= */

document.addEventListener("keydown", function(event) {
    // Escape key closes modals and dropdowns
    if (event.key === "Escape") {
        closeEmailModal();
        closeSettingsModal();
        closeProfileModal();
        toggleSidebar(false);
        const drop = document.getElementById("notificationDropdown");
        if (drop) drop.classList.add("hidden");
    }

    // Ctrl/Cmd + K: Shortcut to Email Analysis
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        const app = document.getElementById("app");
        if (app && !app.classList.contains("hidden")) {
            showPage("analysis");
            setTimeout(() => {
                const txt = document.getElementById("emailContent");
                if (txt) txt.focus();
            }, 100);
        }
    }
});

// Close notifications dropdown when clicking outside
document.addEventListener("click", function(event) {
    const notifWrapper = document.querySelector(".notification-wrapper");
    const dropdown = document.getElementById("notificationDropdown");
    if (dropdown && !dropdown.classList.contains("hidden")) {
        if (notifWrapper && !notifWrapper.contains(event.target)) {
            dropdown.classList.add("hidden");
        }
    }
});


/* =========================================================
   21. APPLICATION BOOTSTRAPPER
========================================================= */

document.addEventListener("DOMContentLoaded", function() {
    // 1. Initialize persistent data store
    loadFromStorage();

    // 2. Initialize default active analysis preview
    if (!appState.activeAnalysisResult && appState.emails.length > 0) {
        const sampleThreat = appState.emails.find(e => e.score >= 60) || appState.emails[0];
        appState.activeAnalysisResult = sampleThreat;
    }

    // 3. Update stats, badges & initial view
    updateAllStatsAndBadges();
    renderCurrentPage();

    // 4. Ensure initial views visibility
    const loginPage = document.getElementById("loginPage");
    const app = document.getElementById("app");

    if (loginPage) loginPage.classList.remove("hidden");
    if (app) app.classList.add("hidden");
});


/* =========================================================
   UTILITIES
========================================================= */

function escapeHTML(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}