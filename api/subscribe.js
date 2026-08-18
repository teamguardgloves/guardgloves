// In-memory IP tracking for Rate Limiting (60 Seconds Cooldown)
const rateLimitMap = new Map();

export default async function handler(req, res) {
  // 1. Only ALLOW POST Method
  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, message: 'Method not allowed' });
  }

  // 2. SECURITY: Rate Limiting Check (1 Request per 60 Seconds per IP against Brute Force)
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  const currentTime = Date.now();
  const windowTime = 60 * 1000; // 60 Seconds

  if (rateLimitMap.has(clientIp)) {
    const lastRequestTime = rateLimitMap.get(clientIp);
    if (currentTime - lastRequestTime < windowTime) {
      return res.status(429).json({ 
        success: false, 
        message: 'Too many requests. Please wait 60 seconds.' 
      });
    }
  }

  // 3. Reject non-JSON content types (Strict Enforcement)
  const contentType = req.headers['content-type'] || '';
  if (!contentType.includes('application/json')) {
    return res.status(400).json({ success: false, message: 'Invalid content type' });
  }

  let { email } = req.body || {};

  // 4. Required Field Check
  if (!email || typeof email !== 'string') {
    return res.status(400).json({ success: false, message: 'Valid email address is required' });
  }

  // 5. SECURITY: Block any Files / Executables / Dangerous Extensions / Scripts
  const containsMaliciousOrExecutableContent = (text) => {
    const dangerousPatterns = [
      // File Extensions & Executables (.exe, .bat, .ps1, .sh, .php, .js, .dll, etc.)
      /\.(exe|pif|application|gadget|msi|msp|com|scr|hta|cpl|msc|jar|bat|cmd|vb|vbs|vbe|js|jse|ws|wsf|wsc|wsh|ps1|ps1xml|ps2|ps2xml|psc1|psc2|msh|msh1|msh2|mshxml|msh1xml|msh2xml|scf|lnk|inf|reg|docm|dotm|xlsm|xltm|xlam|pptm|potm|ppam|ppsm|sldm|php|php3|php4|php5|phtml|py|sh|cgi|pl|dll|so|elf|apk|dmg|iso)\b/i,
      
      // XSS, Injection, and Payload Keywords
      /<script/i,
      /javascript:/i,
      /data:/i,
      /onerror=/i,
      /onload=/i,
      /eval\(/i,
      /exec\(/i,
      /<iframe/i,
      /<embed/i,
      /<object/i,
      /cmd\.exe/i,
      /powershell/i,
      /base64/i
    ];

    return dangerousPatterns.some((pattern) => pattern.test(text));
  };

  const rawPayload = JSON.stringify(req.body);
  if (containsMaliciousOrExecutableContent(rawPayload)) {
    return res.status(400).json({ success: false, message: 'Blocked: Dangerous content or file extension detected.' });
  }

  // 6. SECURITY: Sanitize Input (Strip HTML and Special Tags)
  const sanitizeInput = (input) => {
    return input
      .replace(/<[^>]*>?/gm, '') // Remove HTML tags
      .replace(/[&<>"']/g, '')   // Remove special characters
      .trim();
  };

  email = sanitizeInput(email).substring(0, 80); // Strict max length (80 chars)

  // 7. SECURITY: Strict Email Format Validation
  // Sirf standard email pattern allow karega (e.g., user@domain.com)
  const strictEmailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (!strictEmailRegex.test(email)) {
    return res.status(400).json({ success: false, message: 'Invalid email address format' });
  }

  // 8. Process Email Sending via Resend
  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
      },
      body: JSON.stringify({
        from: 'Guard Gloves Newsletter <onboarding@resend.dev>',
        to: ['teamguardgloves@gmail.com'],
        subject: `New Newsletter Subscriber: ${email}`,
        html: `
          <div style="font-family: Arial, sans-serif; padding: 20px; color: #333; max-width: 600px; border: 1px solid #eee; border-radius: 8px;">
            <h2 style="color: #dc2626; border-bottom: 2px solid #dc2626; padding-bottom: 8px;">New Inner Circle Subscriber</h2>
            <p>A new user has subscribed to the Guard Gloves newsletter from the website footer.</p>
            <p style="background: #f9f9f9; padding: 12px; border-radius: 5px; font-size: 16px;"><strong>Email:</strong> ${email}</p>
          </div>
        `,
      }),
    });

    if (response.ok) {
      rateLimitMap.set(clientIp, currentTime);
      return res.status(200).json({ success: true, message: 'Subscribed successfully!' });
    } else {
      const data = await response.json();
      return res.status(400).json({ success: false, error: data });
    }
  } catch (error) {
    return res.status(500).json({ success: false, error: 'Internal Server Error' });
  }
}