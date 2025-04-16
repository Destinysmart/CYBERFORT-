/**
 * Formats a phone number for display
 * @param phoneNumber The raw phone number
 * @returns Formatted phone number
 */
export function formatPhoneNumber(phoneNumber: string): string {
  // Remove non-digits
  const cleaned = phoneNumber.replace(/\D/g, '');
  
  // Format based on length and starting digits
  if (cleaned.startsWith('1') && cleaned.length === 11) {
    // US format: +1 (XXX) XXX-XXXX
    return `+1 (${cleaned.slice(1, 4)}) ${cleaned.slice(4, 7)}-${cleaned.slice(7, 11)}`;
  } else if (cleaned.length === 10 && !phoneNumber.startsWith('+')) {
    // Assume US without country code: (XXX) XXX-XXXX
    return `(${cleaned.slice(0, 3)}) ${cleaned.slice(3, 6)}-${cleaned.slice(6, 10)}`;
  } else if (phoneNumber.startsWith('+')) {
    // International format with a + already, leave as is
    return phoneNumber;
  } else {
    // Add a + if it appears to be international but missing the +
    return phoneNumber.startsWith('00') 
      ? `+${phoneNumber.slice(2)}` 
      : `+${phoneNumber}`;
  }
}

/**
 * Validates if a string is a potentially valid phone number
 * @param phoneNumber The phone number to validate
 * @returns Boolean indicating if the phone number is valid
 */
export function isValidPhoneNumber(phoneNumber: string): boolean {
  // Remove all non-digits except +
  const cleaned = phoneNumber.replace(/[^\d+]/g, '');
  
  // Check if it has enough digits to be a valid number
  // Most international numbers are between 8 and 15 digits including country code
  return cleaned.length >= 8 && cleaned.length <= 15;
}

/**
 * Extracts country code from phone number
 * @param phoneNumber The phone number
 * @returns The country code or null if not found
 */
export function extractCountryCode(phoneNumber: string): string | null {
  const cleaned = phoneNumber.replace(/\D/g, '');
  
  // Common country codes
  const countryCodes = [
    '1', // US, Canada
    '44', // UK
    '61', // Australia
    '33', // France
    '49', // Germany
    '81', // Japan
    '86', // China
    '91'  // India
  ];
  
  // Try to match the start of the number with known country codes
  for (const code of countryCodes) {
    if (cleaned.startsWith(code)) {
      return code;
    }
  }
  
  // Return null if no match
  return null;
}
