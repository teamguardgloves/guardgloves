export default async function handler(req, res) {
  // 1. Only ALLOW POST Method
  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, message: 'Method not allowed' });
  }

  // 2. Reject non-JSON content types (Prevents direct File Upload Exploits)
  const contentType = req.headers['content-type'] || '';
  if (!contentType.includes('application/json')) {
    return res.status(400).json({ success: false, message: 'Invalid content type' });
  }

  let { name, company, email, country, phone, projectType, category, quantity, details } = req.body || {};

  // 3. Required Fields Check
  if (!name || !email || !company || !country || !projectType || !category || !details) {
    return res.status(400).json({ success: false, message: 'Required fields are missing' });
  }

  // 4. SECURITY: Helper function to strip HTML / Script Tags (XSS Protection)
  const sanitizeInput = (input) => {
    if (typeof input !== 'string') return '';
    return input
      .replace(/<[^>]*>?/gm, '') // Remove HTML tags
      .replace(/[&<>"']/g, '')   // Remove special HTML characters
      .trim();
  };

  // 5. SECURITY: Check for suspicious hacking payloads/keywords
  const containsMaliciousContent = (text) => {
    const suspiciousPatterns = [
      /<script/i,
      /javascript:/i,
      /onerror=/i,
      /onload=/i,
      /eval\(/i,
      /exec\(/i,
      /union\s+select/i,
      /select\s+.*\s+from/i,
      /drop\s+table/i,
      /<iframe/i,
    ];
    return suspiciousPatterns.some((pattern) => pattern.test(text));
  };

  const rawPayload = JSON.stringify(req.body);
  if (containsMaliciousContent(rawPayload)) {
    return res.status(400).json({ success: false, message: 'Malicious content detected' });
  }

  // 6. Sanitize and enforce strict Max Lengths
  name = sanitizeInput(name).substring(0, 60);
  company = sanitizeInput(company).substring(0, 80);
  email = sanitizeInput(email).substring(0, 100);
  country = sanitizeInput(country).substring(0, 50);
  phone = sanitizeInput(phone || 'N/A').substring(0, 30);
  projectType = sanitizeInput(projectType).substring(0, 50);
  category = sanitizeInput(category).substring(0, 50);
  quantity = sanitizeInput(quantity || 'N/A').substring(0, 50);
  details = sanitizeInput(details).substring(0, 2000);

  // 7. SECURITY: Strict Email Format Validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ success: false, message: 'Invalid email address' });
  }

  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
      },
      body: JSON.stringify({
        from: 'Guard Gloves Contact <onboarding@resend.dev>',
        to: ['teamguardgloves@gmail.com'],
        subject: `New Project Inquiry from ${name} (${company})`,
        html: `
          <div style="font-family: Arial, sans-serif; padding: 20px; color: #333; max-width: 600px; border: 1px solid #eee; border-radius: 8px;">
            <h2 style="color: #dc2626; border-bottom: 2px solid #dc2626; padding-bottom: 8px;">New Project Inquiry</h2>
            <p><strong>Name:</strong> ${name}</p>
            <p><strong>Company:</strong> ${company}</p>
            <p><strong>Email:</strong> ${email}</p>
            <p><strong>Country:</strong> ${country}</p>
            <p><strong>Phone / WhatsApp:</strong> ${phone}</p>
            <p><strong>Project Type:</strong> ${projectType}</p>
            <p><strong>Product Category:</strong> ${category}</p>
            <p><strong>Estimated Quantity:</strong> ${quantity}</p>
            <hr style="border: none; border-top: 1px solid #ddd; margin: 15px 0;">
            <p><strong>Project Details:</strong></p>
            <p style="background: #f9f9f9; padding: 15px; border-radius: 5px; white-space: pre-wrap;">${details}</p>
          </div>
        `,
      }),
    });

    const data = await response.json();

    if (response.ok) {
      return res.status(200).json({ success: true, message: 'Inquiry sent successfully!' });
    } else {
      return res.status(400).json({ success: false, error: data });
    }
  } catch (error) {
    return res.status(500).json({ success: false, error: 'Internal Server Error' });
  }
}