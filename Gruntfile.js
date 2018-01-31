

module.exports = function(grunt){
  grunt.initConfig({
    browserify: {
      dist: {
        src:'./index.js',
        dest:'dist/acme.js'
      }
    }
  });
  grunt.loadNpmTasks('grunt-browserify')

  grunt.registerTask('default', ['browserify']);
}
