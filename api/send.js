export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, message: 'Method not allowed' });
  }

  // File upload attempts reject karein
  const contentType = req.headers['content-type'] || '';
  if (!contentType.includes('application/json')) {
    return res.status(400).json({ success: false, message: 'Invalid content type' });
  }

  let { name, email, message } = req.body || {};

  if (!name || !email || !message) {
    return res.status(400).json({ success: false, message: 'All fields are required' });
  }

  // String Trimming & Max Length Sanitization
  name = String(name).trim().substring(0, 60);
  email = String(email).trim().substring(0, 100);
  message = String(message).trim().substring(0, 2000);

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
        subject: `New Global Inquiry from ${name}`,
        html: `
          <div style="font-family: Arial, sans-serif; padding: 20px; color: #333;">
            <h2 style="color: #111;">New Inquiry Received</h2>
            <p><strong>Name:</strong> ${name}</p>
            <p><strong>Email:</strong> ${email}</p>
            <p><strong>Message:</strong></p>
            <p style="background: #f4f4f4; padding: 15px; border-radius: 5px;">${message}</p>
          </div>
        `,
      }),
    });

    const data = await response.json();

    if (response.ok) {
      return res.status(200).json({ success: true, message: 'Email sent successfully!' });
    } else {
      return res.status(400).json({ success: false, error: data });
    }
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
}