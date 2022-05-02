async function parse(scanResults) {

  if (typeof(scanResults) === "string") // empty file
    return [];
    
  const findings = [];

  for (let i = 0; i < scanResults.matches.length; i++) {
      findings.push({
          name: "Grype scan image " + scanResults.source.target.tags[0],
          description: scanResults.matches[i].vulnerability.id,
          category: "Grype scan image",
          location: scanResults.source.target.userInput,
          osi_layer: "APPLICATION",
          severity: scanResults.matches[i].vulnerability.severity.toUpperCase(),
          reference: {},
          confidence: scanResults.matches[i].vulnerability.urls,
          attributes: {}
      })
    }
    
  return findings;
}

module.exports.parse = parse;