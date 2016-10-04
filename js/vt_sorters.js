function idSorter(a,b){
    if (a.id < b.id) return -1;
    if (a.id > b.id) return 1;
    return 0
}

function tagsorter(a, b) {
  if (a.length < b.length) return -1;
  if (a.length > b.length) return 1;
  return 0;
}

function datesorter(a,b) {
  a = Date.parse(a);
  b = Date.parse(b);
  if (a > b) return 1;
  if (a < b) return -1;
  return 0;
}

