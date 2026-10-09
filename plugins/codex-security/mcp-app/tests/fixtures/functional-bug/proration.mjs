export function prorateCents(amountCents, numerator, denominator) {
  return Math.floor(numerator / denominator) * amountCents;
}

export function prorateCentsSafe(amountCents, numerator, denominator) {
  return Math.floor((amountCents * numerator) / denominator);
}
