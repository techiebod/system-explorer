// Typed narrowing. The ONE interaction the platform has no answer for:
// Ctrl-F highlights a match, it does not remove the 270 rows between the
// matches.
//
// DESIGN §27's line, which binds this file as it binds the templates:
// SCRIPT MAY CHANGE WHAT IS SHOWN; IT MAY NEVER DECIDE WHAT A THING
// MEANS. So this reads the rendered text of rows and sets their
// visibility, and does none of the following, each of which is a
// specific trap this product has already fallen into:
//
//   - read a fact's declaration, type or unit — the unit guesser §27
//     records did not know `Usec` and rendered every microsecond fact as
//     a bare integer;
//   - compute or restyle a severity — three severity tables drifted from
//     the rulebook;
//   - mint a link — a routing table of 31 id prefixes went stale and
//     nothing in the browser could have noticed, because nothing in the
//     browser mints ids;
//   - reorder rows — sorting needs the producer's typed values, not the
//     rendered strings, and "1 GiB" against "512 B" is exactly the
//     comparison a renderer must not invent;
//   - change any server-rendered count — the facet and hide-group chips
//     answer what a group HOLDS, not what is showing, and that invariant
//     is held by the server rendering them;
//   - remove a row from the DOM, or write the filter into the URL. A URL
//     carrying a filter the server does not apply is a URL that lies to
//     whoever pastes it.
(function () {
  "use strict";
  var box = document.getElementById("narrow");
  var table = document.querySelector("main table tbody");
  if (!box || !table) return;

  // The control is rendered hidden and revealed HERE, so a client
  // without script is never shown a dead input.
  var shell = document.getElementById("narrow-shell");
  if (shell) shell.hidden = false;

  var status = document.getElementById("narrow-status");
  var rows = Array.prototype.slice.call(table.rows);
  // One lowercased string per row, cached on first use. Display state,
  // not knowledge.
  var text = null;

  function apply() {
    var terms = box.value.toLowerCase().split(/\s+/).filter(Boolean);
    if (text === null) {
      text = rows.map(function (row) { return row.textContent.toLowerCase(); });
    }
    var shown = 0, hiddenByGroup = 0;
    for (var i = 0; i < rows.length; i++) {
      var hit = true;
      for (var t = 0; t < terms.length; t++) {
        if (text[i].indexOf(terms[t]) === -1) { hit = false; break; }
      }
      rows[i].toggleAttribute("data-narrowed", !hit);
      if (!hit) continue;
      shown++;
      // A row inside a hide group the reader has not revealed is a match
      // they cannot see. Counted separately and said, because a match
      // suppressed by two mechanisms with only one of them named is the
      // same defect the server already guards against.
      if (rows[i].hasAttribute("data-group")) hiddenByGroup++;
    }
    if (!status) return;
    if (!terms.length) { status.textContent = ""; return; }
    var said = "showing " + shown + " of " + rows.length + " rows";
    if (hiddenByGroup) {
      said += " — " + hiddenByGroup + " of them are inside groups you have " +
        "hidden; reveal those above to see them";
    }
    status.textContent = said;
  }

  box.addEventListener("input", apply);
  // `/` focuses it, Escape clears and returns focus to the table — the
  // platform's answer to walking a 300-row table is ~300 tab stops.
  document.addEventListener("keydown", function (e) {
    var typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
    if (e.key === "/" && !typing) { e.preventDefault(); box.focus(); return; }
    if (e.key === "Escape" && document.activeElement === box) {
      box.value = ""; apply(); box.blur();
    }
  });
  apply();
})();
