/** CSV export helpers: formulas from evidence text are neutralised, unknown offsets are not printed as 0x0. */
import { csvCell, formatOffset } from '../renderer/utils/csv';

function assert(condition: boolean, msg: string) {
  if (!condition) {
    console.error(`[FAIL] ${msg}`);
    process.exit(1);
  }
  console.log(`[PASS] ${msg}`);
}

assert(csvCell('=HYPERLINK("http://x")') === `"'=HYPERLINK(""http://x"")"`, 'leading = is neutralised and quotes are doubled');
assert(csvCell('+91 98765') === `"'+91 98765"`, 'leading + is neutralised');
assert(csvCell('hello # world, with comma') === '"hello # world, with comma"', 'ordinary text (including # and comma) is kept');
assert(csvCell(null) === '""', 'null becomes an empty cell');
assert(formatOffset(undefined) === 'not recorded', 'unknown offset is "not recorded"');
assert(formatOffset(-1) === 'not recorded', '-1 means not recorded');
assert(formatOffset(0) === '0x00000000', 'a real offset of 0 is printed');
assert(formatOffset(255) === '0x000000FF', 'offset formatting');
