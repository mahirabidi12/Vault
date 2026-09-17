function padLeft(str, length, char) {
  str = String(str);
  char = char || ' ';
  while (str.length < length) str = char + str;
  return str;
}
module.exports = { padLeft };
