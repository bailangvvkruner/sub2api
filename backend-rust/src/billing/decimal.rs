use std::{error::Error, fmt, str::FromStr};

const SCALE_DIGITS: u32 = 18;
const SCALE: i128 = 1_000_000_000_000_000_000;
const SCALE_U128: u128 = 1_000_000_000_000_000_000;

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Decimal(i128);

impl Decimal {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(SCALE);

    /// Creates a decimal from an integer.
    ///
    /// # Errors
    ///
    /// Returns an error when scaling the integer would overflow.
    pub fn from_integer(value: i128) -> Result<Self, DecimalError> {
        value
            .checked_mul(SCALE)
            .map(Self)
            .ok_or(DecimalError::Overflow)
    }

    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    #[must_use]
    pub const fn is_negative(self) -> bool {
        self.0 < 0
    }

    #[must_use]
    pub const fn scaled_value(self) -> i128 {
        self.0
    }

    /// Adds two fixed-point values.
    ///
    /// # Errors
    ///
    /// Returns an error when the result is outside the fixed-point range.
    pub fn checked_add(self, other: Self) -> Result<Self, DecimalError> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or(DecimalError::Overflow)
    }

    /// Subtracts two fixed-point values.
    ///
    /// # Errors
    ///
    /// Returns an error when the result is outside the fixed-point range.
    pub fn checked_sub(self, other: Self) -> Result<Self, DecimalError> {
        self.0
            .checked_sub(other.0)
            .map(Self)
            .ok_or(DecimalError::Overflow)
    }

    /// Multiplies a fixed-point value by an unsigned integer.
    ///
    /// # Errors
    ///
    /// Returns an error when the integer cannot fit in `i128` or the result
    /// overflows.
    pub fn checked_mul_u64(self, other: u64) -> Result<Self, DecimalError> {
        let other = i128::from(other);
        self.0
            .checked_mul(other)
            .map(Self)
            .ok_or(DecimalError::Overflow)
    }

    /// Multiplies two fixed-point values, rounding half away from zero at the
    /// eighteenth decimal place.
    ///
    /// # Errors
    ///
    /// Returns an error when the rounded result overflows.
    pub fn checked_mul(self, other: Self) -> Result<Self, DecimalError> {
        let left = self.0.unsigned_abs();
        let right = other.0.unsigned_abs();
        let left_integer = left / SCALE_U128;
        let left_fraction = left % SCALE_U128;
        let right_integer = right / SCALE_U128;
        let right_fraction = right % SCALE_U128;

        // (a*S + b) * (c*S + d) / S
        // = a*c*S + a*d + b*c + b*d/S.
        let integer_product = left_integer
            .checked_mul(right_integer)
            .and_then(|value| value.checked_mul(SCALE_U128))
            .ok_or(DecimalError::Overflow)?;
        let left_cross = left_integer
            .checked_mul(right_fraction)
            .ok_or(DecimalError::Overflow)?;
        let right_cross = right_integer
            .checked_mul(left_fraction)
            .ok_or(DecimalError::Overflow)?;
        let fractional_product = left_fraction
            .checked_mul(right_fraction)
            .ok_or(DecimalError::Overflow)?;
        let fractional_quotient = fractional_product / SCALE_U128;
        let fractional_remainder = fractional_product % SCALE_U128;

        let mut magnitude = integer_product
            .checked_add(left_cross)
            .and_then(|value| value.checked_add(right_cross))
            .and_then(|value| value.checked_add(fractional_quotient))
            .ok_or(DecimalError::Overflow)?;
        if fractional_remainder >= SCALE_U128 / 2 {
            magnitude = magnitude.checked_add(1).ok_or(DecimalError::Overflow)?;
        }
        let negative = self.0.is_negative() ^ other.0.is_negative();
        signed_magnitude(magnitude, negative).map(Self)
    }

    /// Formats the value with exactly `places` fractional digits, rounding
    /// half away from zero.
    ///
    /// # Errors
    ///
    /// Returns an error when `places` is greater than 18 or rounding overflows.
    pub fn format_fixed(self, places: u32) -> Result<String, DecimalError> {
        if places > SCALE_DIGITS {
            return Err(DecimalError::InvalidScale(places));
        }

        let divisor = pow10(SCALE_DIGITS - places)?;
        let quotient = self.0 / divisor;
        let remainder = self.0 % divisor;
        let rounded = round_quotient(quotient, remainder, divisor)?;
        Ok(format_scaled(rounded, places))
    }
}

fn signed_magnitude(magnitude: u128, negative: bool) -> Result<i128, DecimalError> {
    if negative {
        if magnitude == i128::MIN.unsigned_abs() {
            return Ok(i128::MIN);
        }
        let value = i128::try_from(magnitude).map_err(|_| DecimalError::Overflow)?;
        value.checked_neg().ok_or(DecimalError::Overflow)
    } else {
        i128::try_from(magnitude).map_err(|_| DecimalError::Overflow)
    }
}

fn round_quotient(quotient: i128, remainder: i128, divisor: i128) -> Result<i128, DecimalError> {
    if remainder.unsigned_abs() < (divisor / 2).unsigned_abs() {
        return Ok(quotient);
    }

    let adjustment = if remainder.is_negative() { -1 } else { 1 };
    quotient
        .checked_add(adjustment)
        .ok_or(DecimalError::Overflow)
}

fn format_scaled(value: i128, places: u32) -> String {
    let negative = value.is_negative();
    let magnitude = value.unsigned_abs();
    if places == 0 {
        return if negative {
            format!("-{magnitude}")
        } else {
            magnitude.to_string()
        };
    }

    let divisor = 10_u128.pow(places);
    let integer = magnitude / divisor;
    let fraction = magnitude % divisor;
    let width = usize::try_from(places).expect("decimal scale fits usize");
    if negative {
        format!("-{integer}.{fraction:0width$}")
    } else {
        format!("{integer}.{fraction:0width$}")
    }
}

fn pow10(exponent: u32) -> Result<i128, DecimalError> {
    10_i128.checked_pow(exponent).ok_or(DecimalError::Overflow)
}

impl FromStr for Decimal {
    type Err = DecimalError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_decimal(input)
    }
}

fn parse_decimal(input: &str) -> Result<Decimal, DecimalError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(DecimalError::InvalidSyntax);
    }

    let bytes = input.as_bytes();
    let mut index = 0;
    let negative = match bytes.first() {
        Some(b'-') => {
            index = 1;
            true
        }
        Some(b'+') => {
            index = 1;
            false
        }
        _ => false,
    };

    let mut coefficient = 0_i128;
    let mut digits = 0_u32;
    let mut fractional_digits = 0_i64;
    let mut after_decimal = false;
    while let Some(byte) = bytes.get(index) {
        match byte {
            b'0'..=b'9' => {
                coefficient = coefficient
                    .checked_mul(10)
                    .and_then(|value| value.checked_add(i128::from(byte - b'0')))
                    .ok_or(DecimalError::Overflow)?;
                digits = digits.checked_add(1).ok_or(DecimalError::Overflow)?;
                if after_decimal {
                    fractional_digits = fractional_digits
                        .checked_add(1)
                        .ok_or(DecimalError::Overflow)?;
                }
                index += 1;
            }
            b'.' if !after_decimal => {
                after_decimal = true;
                index += 1;
            }
            b'e' | b'E' => break,
            _ => return Err(DecimalError::InvalidSyntax),
        }
    }

    if digits == 0 || (after_decimal && bytes.get(index.wrapping_sub(1)) == Some(&b'.')) {
        return Err(DecimalError::InvalidSyntax);
    }

    let exponent = if matches!(bytes.get(index), Some(b'e' | b'E')) {
        index += 1;
        parse_exponent(bytes, &mut index)?
    } else {
        0
    };
    if index != bytes.len() {
        return Err(DecimalError::InvalidSyntax);
    }

    if coefficient == 0 {
        return Ok(Decimal::ZERO);
    }

    let power = i64::from(SCALE_DIGITS)
        .checked_add(exponent)
        .and_then(|value| value.checked_sub(fractional_digits))
        .ok_or(DecimalError::Overflow)?;
    let scaled = if power >= 0 {
        let power = u32::try_from(power).map_err(|_| DecimalError::Overflow)?;
        coefficient
            .checked_mul(pow10(power)?)
            .ok_or(DecimalError::Overflow)?
    } else {
        let divisor_power = power.checked_neg().ok_or(DecimalError::Overflow)?;
        let divisor_power = u32::try_from(divisor_power).map_err(|_| DecimalError::Overflow)?;
        let divisor = pow10(divisor_power).map_err(|_| DecimalError::PrecisionExceeded)?;
        if coefficient % divisor != 0 {
            return Err(DecimalError::PrecisionExceeded);
        }
        coefficient / divisor
    };

    if negative {
        scaled
            .checked_neg()
            .map(Decimal)
            .ok_or(DecimalError::Overflow)
    } else {
        Ok(Decimal(scaled))
    }
}

fn parse_exponent(bytes: &[u8], index: &mut usize) -> Result<i64, DecimalError> {
    let negative = match bytes.get(*index) {
        Some(b'-') => {
            *index += 1;
            true
        }
        Some(b'+') => {
            *index += 1;
            false
        }
        _ => false,
    };

    let start = *index;
    let mut exponent = 0_i64;
    while let Some(b'0'..=b'9') = bytes.get(*index) {
        exponent = exponent
            .checked_mul(10)
            .and_then(|value| value.checked_add(i64::from(bytes[*index] - b'0')))
            .ok_or(DecimalError::Overflow)?;
        *index += 1;
    }
    if *index == start {
        return Err(DecimalError::InvalidSyntax);
    }

    if negative {
        exponent.checked_neg().ok_or(DecimalError::Overflow)
    } else {
        Ok(exponent)
    }
}

impl fmt::Display for Decimal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut rendered = format_scaled(self.0, SCALE_DIGITS);
        if rendered.contains('.') {
            while rendered.ends_with('0') {
                rendered.pop();
            }
            if rendered.ends_with('.') {
                rendered.pop();
            }
        }
        formatter.write_str(&rendered)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecimalError {
    InvalidSyntax,
    PrecisionExceeded,
    InvalidScale(u32),
    Overflow,
}

impl fmt::Display for DecimalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSyntax => formatter.write_str("invalid decimal syntax"),
            Self::PrecisionExceeded => formatter.write_str("decimal exceeds 18 fractional digits"),
            Self::InvalidScale(scale) => write!(formatter, "decimal scale {scale} exceeds 18"),
            Self::Overflow => formatter.write_str("decimal arithmetic overflow"),
        }
    }
}

impl Error for DecimalError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_scientific_notation_exactly() {
        assert_eq!(
            "1.25e-06".parse::<Decimal>().unwrap().to_string(),
            "0.00000125"
        );
        assert_eq!("-12.3400".parse::<Decimal>().unwrap().to_string(), "-12.34");
        assert_eq!("2E3".parse::<Decimal>().unwrap().to_string(), "2000");
    }

    #[test]
    fn rejects_unrepresentable_precision_and_overflow() {
        assert_eq!(
            "0.0000000000000000001".parse::<Decimal>(),
            Err(DecimalError::PrecisionExceeded)
        );
        assert_eq!(
            "999999999999999999999999999999999999999".parse::<Decimal>(),
            Err(DecimalError::Overflow)
        );
    }

    #[test]
    fn multiplication_and_database_formatting_are_checked() {
        let amount = "0.00000125"
            .parse::<Decimal>()
            .unwrap()
            .checked_mul_u64(1_000_000)
            .unwrap();
        assert_eq!(amount.to_string(), "1.25");
        assert_eq!(amount.format_fixed(10).unwrap(), "1.2500000000");

        let rounded = "1.234567895".parse::<Decimal>().unwrap();
        assert_eq!(rounded.format_fixed(8).unwrap(), "1.23456790");

        let large = "100000000000000000000".parse::<Decimal>().unwrap();
        let tenth = "0.1".parse::<Decimal>().unwrap();
        assert_eq!(
            large.checked_mul(tenth).unwrap().to_string(),
            "10000000000000000000"
        );
    }
}
