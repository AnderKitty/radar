// Pure helpers for the "Información pública accesible" section. No DOM and no
// side effects, so it can be unit-tested under Node and reused by app.js.
(function (root) {
  'use strict';

  var CATEGORIES = {
    camara_publica:  { label: 'Cámaras públicas',      color: '#4493f8' },
    sensor_transito: { label: 'Sensores de tránsito',  color: '#3fb950' },
    alumbrado:       { label: 'Alumbrado inteligente', color: '#d4a72c' },
    riego:           { label: 'Riego automático',      color: '#2dd4bf' },
    api_municipal:   { label: 'APIs municipales',      color: '#bc8cff' },
    dato_abierto:    { label: 'Datos abiertos',        color: '#f0883e' },
    otro:            { label: 'Otros',                 color: '#8b98a5' }
  };

  function categoryMeta(cat) {
    return CATEGORIES[cat] || CATEGORIES.otro;
  }

  function filterByCategory(entries, category) {
    if (!category || category === 'all') return entries.slice();
    return entries.filter(function (e) { return e.category === category; });
  }

  function countByCategory(entries) {
    var counts = {};
    entries.forEach(function (e) {
      var key = CATEGORIES[e.category] ? e.category : 'otro';
      counts[key] = (counts[key] || 0) + 1;
    });
    return counts;
  }

  var api = {
    CATEGORIES: CATEGORIES,
    categoryMeta: categoryMeta,
    filterByCategory: filterByCategory,
    countByCategory: countByCategory
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  } else {
    root.Registry = api;
  }
})(typeof window !== 'undefined' ? window : this);
