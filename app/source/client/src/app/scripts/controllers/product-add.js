'use strict';

/**
 * @ngdoc function
 * @name clientApp.controller:ProductAddCtrl
 * @description
 * # ProductAddCtrl
 * Controller of the clientApp
 */
angular.module('clientApp').controller('ProductAddCtrl', function ($scope, $location, $http, $route, Constants) {
    $scope.addProduct = true;

    $scope.saveProduct = function() {
      var product = {
        title: $scope.product.title,
        unitCost: $scope.product.unitCost
      };

      $http.post(Constants.PRODUCT_MANAGER_URL + '/product', product)
        .then(function(response) {
          console.log('Product added');
          $scope.product.title = '';
          $scope.product.unitCost = 0;
          $route.reload();
        })
        .catch(function(response) {
          $scope.error = "Error saving product: " + response.message;
          console.log("Error saving product: " + response.message);
        })
    };

    $scope.cancel = function() {
      $location.path('/products');
    };
  });
