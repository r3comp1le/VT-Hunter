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

