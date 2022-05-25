/**
 * This module contains functions which support
 * advanced / customize input behaviors.
 */
'use strict';

define([
  'app/splunk_app_aws/js/libs/underscore',
  'splunkjs/mvc/multidropdownview'
], function(
  _,
  MultiDropdownView
) {
  return {
    multiSelectVal: function() {
      /**
       * Supports "*" value for multiselect input.
       * When values other than "*" are selected, '*' should be removed and only selected value applied.
       * If the user select '*' again, then remove all other values.
       */
      var newValue = arguments[0];
      if (_.isArray(newValue) && newValue.length > 1) {
        var allPos = newValue.indexOf('*');

        // if '*' is selected previously, then remove '*'
        if (allPos === 0) {
          newValue = _.without(newValue, '*');
        } else if (allPos === newValue.length - 1) {
          // if '*' is newly selected, then remove all previous values
          newValue = ['*'];
        }

        arguments[0] = newValue;
      }

      return MultiDropdownView.prototype.val.apply(this, arguments);
    },

    multiSelectVal_persist_all: function() {
        
        var newValue = arguments[0];
        if(_.isArray(newValue) && newValue.length==0){arguments[0]="*";}
        if (_.isArray(newValue) && newValue.length > 1) {
            var allPos = newValue.indexOf("*");
            0 === allPos ? newValue = _.without(newValue, "*") : allPos === newValue.length - 1 && (newValue = ["*"]), arguments[0] = newValue
        }
        return MultiDropdownView.prototype.val.apply(this, arguments)
    }



  };
});
